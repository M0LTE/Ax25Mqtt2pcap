# Ax25Mqtt2pcap

Grab AX.25 frames from an MQTT topic and write them to a Wireshark-compatible pcap file.

For a serial-to-TCP proxy for serial KISS modems, including MQTT support, see [kissproxy](https://github.com/M0LTE/kissproxy).

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y8KFHA0)

Build:

Install .NET 7 SDK, then:
```
cd Ax25Mqtt2pcap
dotnet build
```

Usage:

`./ax25mqtt2pcap mymqttserver`

or if you can't be bothered compiling it first:

```
cd Ax25Mqtt2pcap 
dotnet run mymqttserver
```

Hard coded to subscribe to topics `kissproxy/+/+/+/unframed/+/DataFrameKissCmd` as output by [kissproxy](https://github.com/M0LTE/kissproxy) but of course, trivial to change.

![image](https://github.com/M0LTE/Ax25Mqtt2pcap/assets/37816024/9da2f2b5-79d4-4e4e-b021-d5aa893fe8f9)

## Licence

MIT. Fill your boots.
