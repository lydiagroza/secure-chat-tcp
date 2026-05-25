using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace SecureChatTCP.Common;

public static class NetworkHelper
{
    // Sends a length-prefixed UTF-8 string: [4-byte LE int][bytes]
    public static async Task SendStringAsync(NetworkStream stream, string text)
    {
        var data = Encoding.UTF8.GetBytes(text);
        var lenBytes = BitConverter.GetBytes(data.Length);
        await stream.WriteAsync(lenBytes);
        await stream.WriteAsync(data);
    }

    // Receives a length-prefixed UTF-8 string.
    public static async Task<string> ReceiveStringAsync(NetworkStream stream)
    {
        var lenBytes = new byte[4];
        await ReadExactAsync(stream, lenBytes);
        var len = BitConverter.ToInt32(lenBytes);
        var data = new byte[len];
        await ReadExactAsync(stream, data);
        return Encoding.UTF8.GetString(data);
    }

    // Serializes a SecurePacket to JSON and sends it.
    public static async Task SendPacketAsync(NetworkStream stream, SecurePacket packet)
    {
        var json = JsonSerializer.Serialize(packet);
        await SendStringAsync(stream, json);
    }

    // Receives and deserializes a SecurePacket.
    public static async Task<SecurePacket?> ReceivePacketAsync(NetworkStream stream)
    {
        var json = await ReceiveStringAsync(stream);
        return JsonSerializer.Deserialize<SecurePacket>(json);
    }

    // Reads exactly buffer.Length bytes from the stream (handles partial reads).
    private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(total));
            if (read == 0) throw new IOException("Connection closed unexpectedly.");
            total += read;
        }
    }
}
