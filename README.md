Handle the SOCKS protocol on libevent bufferevents.

I didn't want to write this code twice. Maybe you don't either.
If you are dealing with SOCKS and libevent, feel free to use this library or steal the code ;-)
If you see something that should or could be done better, feel free to complain or open a pull-request.

```
LD_LIBRARY_PATH=bin/ ./bin/sockscat --nossl --dst-host www.google.de --dst-port 80 --proxy-host 127.0.0.1 --proxy-port 1080
GET / HTTP/1.1

HTTP/1.1 302 Found
..
```
