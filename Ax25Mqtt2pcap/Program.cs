using MQTTnet;
using MQTTnet.Client;
using MQTTnet.Extensions.ManagedClient;
using NAx25;
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using static System.Console;

ResetColor();

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
//await mqttClient.SubscribeAsync("kissproxy/+/+/+/debug");
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

int cur = 0;
Stopwatch sw = Stopwatch.StartNew();
Dictionary<string, int> lastSeqs = new Dictionary<string, int>();
mqttClient.ApplicationMessageReceivedAsync += arg =>
{
    if (arg.ApplicationMessage.Topic.Contains("DataFrameKissCmd"))
    {
        var timestamp = DateTime.UtcNow - DateTime.UnixEpoch;
        var payload = arg.ApplicationMessage.PayloadSegment;

        lock (fileStream)
        {
            writer.WriteRecordHeader(timestamp, payload.Count);
            writer.Write(payload);
            writer.Flush();
        }

        var decodeOutput = DecodeAx25(payload);
        if (!string.IsNullOrWhiteSpace(decodeOutput))
        {
            WriteLine($"{DateTime.UtcNow:HH:mm:ss}Z  {decodeOutput}");
        }
    }
    else if (false && arg.ApplicationMessage.Topic.Contains("debug"))
    {
        var obj = JsonNode.Parse(arg.ApplicationMessage.ConvertPayloadToString());
        int seq = (int)obj!["seq"]!;
        string hex = (string)obj!["val"]!;

        if (hex.Length == 1)
        {
            hex = "0" + hex;
        }
        byte val = Convert.FromHexString(hex).Single();

        if (!lastSeqs.TryGetValue(arg.ApplicationMessage.Topic, out var topicLastSeq))
        {
            lastSeqs[arg.ApplicationMessage.Topic] = seq;
        }

        if (topicLastSeq != 0)
        {
            if (seq < topicLastSeq + 1)
            {
                // gone backwards
                BackgroundColor = ConsoleColor.Red;
            }
            else if (seq > topicLastSeq + 1)
            {
                // missed some
                BackgroundColor = ConsoleColor.Yellow;
            }
            else
            {
                lastSeqs[arg.ApplicationMessage.Topic] = seq;
                ResetColor();
            }
        }

        if (arg.ApplicationMessage.Topic == "kissproxy/gb7rdg-node/platform-3f980000.usb-usb-0:1.3:1.0/toModem/debug")
        {
            if (sw.ElapsedMilliseconds > 100)
            {
                cur = 0;
                WriteLine();
                WriteLine();
            }
            sw.Restart();

            cur++;
            if (hex == "c0")
            {
                ForegroundColor = ConsoleColor.Green;
            }
            Write(hex);
            ResetColor();
            Write(" ");
            if (cur == 8)
            {
                Write(" ");
            }
            var (left, top) = GetCursorPosition();
            bool isSecondByte = cur > 8;
            SetCursorPosition(50 + cur + (isSecondByte ? 2 : 0), top);
            if (val >= 33 && val <= 126)
            {
                Write(Encoding.ASCII.GetString(new[] { val }));
            }
            else
            {
                Write(".");
            }
            SetCursorPosition(left, top);

            if (cur == 16)
            {
                cur = 0;
                WriteLine();
            }
        }
    }
    return Task.CompletedTask;
};


WriteLine("Running, press enter to stop");
ReadLine();

static string? DecodeAx25(ArraySegment<byte> payload)
{
    try
    {
        if (!Frame.TryParse(payload, out var frame))
        {
            return null;
        }

        return frame.ToString();
    }
    catch (Exception ex)
    {
        var test = @$"
[Fact]
public void DecodeException_{Guid.NewGuid()}()
{{
    // {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}
    // {ex.GetType().Name}: {ex.Message}
    Frame.TryParse(Convert.FromHexString(""{Convert.ToHexString(payload)}""), out var frame).Should().BeTrue();
}}";

        File.AppendAllText("GeneratedUnitTests.txt", test);

        WriteLine("Error decoding a frame, generated a test");

        return null;
    }
}
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