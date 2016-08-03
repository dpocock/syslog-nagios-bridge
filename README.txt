

syslog-nagios-bridge


Copyright (C) 2014 Daniel Pocock http://danielpocock.com


https://github.com/dpocock/syslog-nagios-bridge



Dependencies
------------

python-netsyslog
    https://github.com/dpocock/python-netsyslog

pynag
    http://pynag.org
    (using latest code from Git, June 2014,
    with the new Utils.CheckResult support)

Installation
------------

Copy syslog-nagios-bridge.py to a suitable location (e.g. /usr/local/bin)

Copy the configuration file to a suitable location (e.g. /etc/nagios3)

Update the config file settings

Edit your syslog daemon, tell it to send events to syslog-nagios-bridge over TCP.
For example, append the following to /etc/rsyslog.conf:

# for rsyslog >= v7.x:
#action(type="omfwd" Target="127.0.0.1" Port="30514" Protocol="tcp" TCP_Framing="octet-counted")
# for rsyslog < v7.x
*.* @@127.0.0.1:30514

Make sure the port number matches the "bind_port" in syslog-bridge.conf

syslog-nagios-bridge.py automatically creates service definitions for each syslog
tag name that it detects.  It can put them directly into the nagios configuration directories
or it can generate them in some other place and you can copy them over manually.

In any case, for Nagios to report on a particular host/syslog tag, there must be
a corresponding service definition in /etc/nagios3/conf.d/whatever.cfg.  To alert
on errors from the httpd process, you may use the following:

define service{
        use                             generic-service
        host_name                       myhost
        service_description             httpd - SysLog
        check_command                   return-unknown
        active_checks_enabled           0
        passive_checks_enabled          1
        max_check_attempts              1
        }

After doing the configuration, start the bridge and restart/reload the
syslog daemon and Nagios itself:

# su - nagios -c /usr/local/bin/syslog-nagios-bridge.py
# service rsyslog restart
# service nagios3 reload

The relevant services will go into the CRITICAL state after error events
are detected by syslog-nagios-bridge.  Nagios has no way to know when
the logs have been checked and whether anybody has taken action to
correct the errors.  Consequently, the services will remain in the CRITICAL
state indefinitely.  A user must go into the Nagios web interface
and use the option "Submit passive check result for this service"
to put the service back in the OK state.  Normally this is only done
after manually investigating the error.

Logging from syslog-nagios-bridge itself
----------------------------------------

syslog-nagios-bridge creates its own logfile, it is defined in
the configuration file.

As it is a Python script, it could be adapted to use the handler for
writing to SysLog.  There is a risk that this could lead to loops
where log messages from syslog-nagios-bridge would be sent to the
SysLog daemon and would come back to syslog-nagios-bridge like any other
messages it is processing.  Therefore, it is recommended that it should
only log to file and care should be taken to monitor the file for errors.

