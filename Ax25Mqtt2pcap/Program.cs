using MQTTnet;
using MQTTnet.Client;
using MQTTnet.Extensions.ManagedClient;
using static System.Console;

if (args.Length != 1)
{
    WriteLine("Specify MQTT server name as the sole command line parameter");
    return;
}

var mqttClient = new MqttFactory().CreateManagedMqttClient();
mqttClient.ConnectedAsync += _ => { WriteLine("Connected to broker"); return Task.CompletedTask; };
mqttClient.ConnectingFailedAsync += _ => { WriteLine("Connecting to broker failed"); return Task.CompletedTask; };
mqttClient.DisconnectedAsync += _ => { WriteLine("Disconnected from broker"); return Task.CompletedTask; };
await mqttClient.SubscribeAsync("kissproxy/+/+/+/unframed/+/DataFrameKissCmd");
await mqttClient.StartAsync(new ManagedMqttClientOptionsBuilder()
    .WithAutoReconnectDelay(TimeSpan.FromSeconds(5))
    .WithClientOptions(new MqttClientOptionsBuilder()
        .WithClientId(Guid.NewGuid().ToString())
        .WithTcpServer(args[0])
        .Build())
    .Build());

using var fileStream = File.Open($"ax25-capture-{DateTime.UtcNow:yyyyMMdd-HHmmss}.pcap", FileMode.Create, FileAccess.Write, FileShare.Read);
using var writer = new BinaryWriter(fileStream);
writer.WritePcapHeader();

mqttClient.ApplicationMessageReceivedAsync += arg =>
{
    var timestamp = DateTime.UtcNow - DateTime.UnixEpoch;
    var payload = arg.ApplicationMessage.PayloadSegment;

    lock (fileStream)
    {
        writer.WriteRecordHeader(timestamp, payload.Count);
        writer.Write(payload);
        writer.Flush();
    }
    WriteLine($"{DateTime.UtcNow:HH:mm:ss}Z  {payload.Count} bytes");
    return Task.CompletedTask;
};

WriteLine("Running, press enter to stop");
ReadLine();

static class Extensions
{
    public static void WritePcapHeader(this BinaryWriter writer)
    {
        writer.Write((UInt32)0xa1b2c3d4); // magic_number
        writer.Write((UInt16)2);          // version_major
        writer.Write((UInt16)4);          // version_minor
        writer.Write((UInt32)0);          // thiszone
        writer.Write((UInt32)0);          // sigfigs
        writer.Write((UInt32)65535);      // snaplen
        writer.Write((UInt32)3);          // network (LINKTYPE_AX25)
        writer.Flush();
    }

    public static void WriteRecordHeader(this BinaryWriter writer, TimeSpan ts, int frameLength)
    {
        var fractionPart = ts.TotalSeconds - (int)ts.TotalSeconds;

        writer.Write((UInt32)ts.TotalSeconds);          // ts_sec
        writer.Write((UInt32)(fractionPart * 1000000)); // ts_usec
        writer.Write((UInt32)frameLength);              // incl_len
        writer.Write((UInt32)frameLength);              // orig_len
    }
}