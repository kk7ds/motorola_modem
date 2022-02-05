Motorola Modem Tool
===================

I wrote this to fetch data from and reboot my Motorola MB 8611 modem. It may work for others, but I haven't tested.

``` console:
$ ./motorola_modem.py -h                                              ✭master
usage: motorola_modem.py [-h] [--username USERNAME] [--password PASSWORD] [--host HOST] [--noauth] action

positional arguments:
  action               One of status,connection,channels,reboot,events,lag,connstatus,uptime

optional arguments:
  -h, --help           show this help message and exit
  --username USERNAME
  --password PASSWORD
  --host HOST
  --noauth             Do not attempt to login before performing action.
```

