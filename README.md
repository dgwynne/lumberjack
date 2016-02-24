A network syslog listener to Bunyan proxy

```
usage: lumberjack [-d] [-l listener] [-u user] [/path/to/logfile]
```

lumberjack is a priv revoking daemon. This means it starts as root,
opens the log file, opens it's listening sockets, and then chroots
and drops privs. The user it drops privs to by default is _lumberjack,
but an alternate user can be specified with -u.

By default lumberjack listens to tcp connections on localhost port
514 unless listeners are specified with -l arguments. A listener
is as a hostname with an optional port and protocol in a URI format
(like the one used in OpenBSDs syslog.conf). Using * for a hostname
will cause the listener to bind to wildcard addresses.  Currently
supported protocols are tcp, tcp4, and tcp6.

If a logfile is not specified lumberjack will log to standard out.

-d causes lumberjack to not daemonise and write errors to stderr.

lumberjack has been written on [OpenBSD](http://www.openbsd.org/)
so that's what the Makefile is for. It's probably not hard to port
elsewhere.

An example of a log message in the format specified by
[Bunyan](https://github.com/trentm/node-bunyan) is:

```json
  {
    "v": 0,
    "level": 35,
    "name": "syslog",
    "hostname": "ozone.eait.uq.edu.au",
    "pid": 0,
    "time": "2016-02-23T01:42:18Z",
    "msg": "sudo:     xdlg : TTY=ttyp2 ; PWD=/server/home/xdlg/lumberjack ; USER=root ; COMMAND=./lumberjack -d -p 514 /var/log/bunyan/test",
    "facility": "authpriv",
    "_": [
      {
        "src": "[127.0.0.1]:3640",
        "dst": "ozone.eait.uq.edu.au",
        "time": "2016-02-23T01:42:18.568Z"
      }
    ]
  }
```

[Bunyan](https://github.com/trentm/node-bunyan) turns that into:

```
[2016-02-23T01:42:18Z] LVL35: syslog/0 on ozone.eait.uq.edu.au: sudo:     xdlg : TTY=ttyp2 ; PWD=/server/home/xdlg/lumberjack ; USER=root ; COMMAND=./lumberjack -d -p 514 /var/log/bunyan/test (facility=authpriv)
    _: [
      {
        "src": "[127.0.0.1]:3640",
        "dst": "ozone.eait.uq.edu.au",
        "time": "2016-02-23T01:42:18.568Z"
      }
    ]
```
