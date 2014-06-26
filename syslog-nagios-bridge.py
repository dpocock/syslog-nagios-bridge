#!/usr/bin/python
#
# syslog-nagios-bridge - transfer Syslog events to Nagios checkresults file
#
# Project page:  https://github.com/dpocock/python-netsyslog
#
# Copyright (C) 2014 Daniel Pocock http://danielpocock.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
############################################################################

import argparse
import logging
import logging.handlers
import netsyslog
import os
import Queue
import re
from threading import Thread
import sys
import syslog
import time

from pynag.Utils import CheckResult

q = Queue.Queue()
hosts = {}

# default values (set from the config file)
log_file = None
log_level = logging.WARNING

# This is a subclass of the SyslogTCPHandler from the netsyslog module.
# It receives a notification (call to handle_message) each time a
# syslog event arrives from the network and it puts them into a queue
# for processing on the main thread.
class MyHandler(netsyslog.SyslogTCPHandler):

    def handle_message(self, frame):
        """Handle parsed Syslog frames.

        """
        logger.debug("severity: %d, facility: %d, tag: %s, PID: %s, host: %s, ts: %s, content: %s" %
            (frame.pri.severity,
            frame.pri.facility,
            frame.msg.tag,
            frame.msg.pid,
            frame.header.hostname,
            frame.header.timestamp,
            frame.msg.content))
        # queue the frame for examination by the main thread
        q.put(frame)

# make sure host names don't contain domain parts
# (some bad syslog implementations send domain parts)
# normalize to lowercase
def clean_host_name(hostname):
    if hostname is None:
        return None
    if hostname == "" or hostname == "-":
        return None
    return hostname.split(".")[0].lower()

# make sure tag names don't contain illegal characters
def clean_tag_name(tag):
    if tag is None:
        return None
    if tag == "" or tag == "-":
        return None
    # FIXME - use something more efficient than a regular expression
    _tag = re.sub(r"\W+", "", tag)
    if tag != _tag:
        logger.warning("detected invalid tag name: %s" % tag)
    return _tag

def make_desc(hostname, tag):
    """Create a service description name.

    Should return names that exactly match the service descriptions
    in the Nagios configuration.

    """

    return tag + " - SysLog"

def lookup_app(hostname, tag):
    """Lookup the properties for the tag/application.

    Look through our in-memory cache for properties related to
    the tag/application on the given host.

    """

    logger = logging.getLogger(__name__)

    if not hostname in hosts.keys():
        _host = {}
        hosts[hostname] = _host
        logger.debug("first event from host: " + hostname)
    else:
        _host = hosts[hostname]

    if not tag in _host.keys():
        _app = {}
        _host[tag] = _app
        logger.debug("first event from tag: " + tag)
        if svc_def_dir is not None:
            # see if we need to create a service defintion for the tag
            _filename = "syslog_%s_%s.cfg" % (hostname, tag)
            svc_def_filename = os.path.join(svc_def_dir, _filename)
            if not os.path.exists(svc_def_filename):
                logger.debug("creating service def for host %s, tag %s" % (hostname, tag))
                # FIXME: can pynag create the service def through the API?
                with open(svc_def_filename, "w") as f:
                    svc_desc = make_desc(hostname, tag)
                    f.write("define service{\n")
                    f.write("        use                             %s\n" % svc_tmpl)
                    f.write("        host_name                       %s\n" % hostname)
                    f.write("        service_description             %s\n" % svc_desc)
                    f.write("        # this is never really executed because active_checks_enabled=0:\n")
                    f.write("        check_command                   %s\n" % svc_check_dummy)
                    f.write("        active_checks_enabled           0\n")
                    f.write("        passive_checks_enabled          1\n")
                    f.write("        # generate email notifications after first error:\n")
                    f.write("        max_check_attempts              1\n")
                    f.write("        }\n")
                
    else:
        _app = _host[tag]

    return _app

def handle_frame(frame):
    """Handle a SysLog event.

    Looks at the event to decide if it should generate a Nagios
    checkresult.

    """

    logger = logging.getLogger(__name__)

    # Get the hostname and tag, lookup the properties for this pair:
    _hostname = clean_host_name(frame.header.hostname)
    if _hostname is None:
        logger.debug("bad or missing hostname, ignoring message")
        return
    _tag = clean_tag_name(frame.msg.tag)
    if _tag is None:
        logger.debug("bad or missing tag, ignoring message")
        return
    _app = lookup_app(_hostname, _tag)

    # Check if we need to notify Nagios
    if frame.pri.severity <= svc_state_threshold:
        if "last_event" in _app.keys():
            if (_app["last_event"] + svc_submission_interval) > time.time():
                # ignore multiple error events with svc_submission_interval
                # seconds after the last checkresult was sent to Nagios
                return
        logger.debug("Must tell Nagios")
        check_result = CheckResult(checkresult_dir)
        desc = make_desc(_hostname, _tag)
        output = "PID=%s, logged: %s" % (frame.msg.pid, frame.msg.content)
        if frame.pri.severity == syslog.LOG_WARNING:
            ret = 1
        else:
            # for LOG_ERR and worse
            ret = 2
        check_result.service_result(
            _hostname,
            desc,
            return_code=ret,
            output=output,
            check_type=1,
            check_options=0,
            scheduled_check=0,
            reschedule_check=0,
            latency=0.1,
            exited_ok=1)
        check_result.submit()
        _app["last_event"] = time.time()

# main program code
if __name__ == '__main__':
    try:
        # parse command line
        parser = argparse.ArgumentParser(description="receive Syslog events and generate Nagios check results file")
        parser.add_argument(
            "config_file",
            nargs="?",
            help="configuration file",
            default="/etc/nagios3/syslog-bridge.conf")
        args = parser.parse_args()

        # read the configuration file
        execfile(args.config_file)

        # Setup logging.
        # *** Be careful not to create a feedback loop ***
        logger = logging.getLogger()
        if log_file is not None:
            logger.addHandler(logging.FileHandler(log_file))
        else:
            logger.addHandler(logging.handlers.SysLogHandler())
        logger.setLevel(log_level)

        # Run the Collector in a thread to listen for incoming connections
        c = netsyslog.Collector(bind_port, MyHandler)
        thread = Thread(target = c.run)
        thread.start()
        while True:
            frame = q.get()
            logger.debug("got a frame from the queue")
            try:
                handle_frame(frame)
            except Exception as e:
                logger.error("Failed to handle an event: %s" % e)
    except Exception as e:
        logging.error("Unexpected failure: %s" % e)
 
