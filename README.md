A network syslog listener to bunyan proxy

```
usage: lumberjack [-46Ad] [-a address] [-p port] [-u user] [/path/to/logfile]
```

By default lumberjack listens on the syslog port on localhost, and
attempts to runs as the _lumberjack user. lumberjack must be started
as root so it can bind to low ports, but chroots to it's users
homedir and drops privs.

The listening address can be specified with -a. -A specifies a
wildcard address. The port lumberjack listens on can be specified
with -p. The address family it listens on can be limited to IPv4
or IPv6 using -4 or -6 respectively.

If a logfile is not specified, lumberjack will log to standard out.

-d causes lumberjack to not daemonise and will write errors to
stderr.

lumberjack has been written on OpenBSD so that's what the Makefile
is for.

An example of a log message is:

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

Bunyan turns that into:

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
