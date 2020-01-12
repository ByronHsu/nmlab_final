# Uplink

Decode the packets sent by the satellite, then query the name.

The packet format looks like this:

```
00AQchan 01nelxxx 10xxxxxx 11xxxxxx

A: abort bit
Q: query bit
channel: channel number
x: data
```

Collect data of 26 packets sent by the satellite, then remove the padding.

> RITSEC{Did_You_lik3_that_latency?}
