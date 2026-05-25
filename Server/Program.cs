using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using SecureChatTCP.Common;

Console.OutputEncoding = Encoding.UTF8;
PrintBanner();

var listener = new TcpListener(IPAddress.Any, 8080);
listener.Start();
Color("[Server] Listening on port 8080...\n", ConsoleColor.Cyan);

using var client = await listener.AcceptTcpClientAsync();
Color($"[Server] Client connected from {client.Client.RemoteEndPoint}\n", ConsoleColor.Green);
listener.Stop();

using var stream = client.GetStream();

// ── Diffie-Hellman Handshake ────────────────────────────────────────────────
Color("[DH] Starting Diffie-Hellman key exchange...", ConsoleColor.Yellow);
Color("[DH] Parameters: p = 2048-bit prime (OpenSSL dhparam), g = 2", ConsoleColor.DarkYellow);

var dh = new DiffieHellman();
var pubStr = dh.PublicKey.ToString();
Color($"[DH] Server Public Key A ({pubStr.Length} digits):", ConsoleColor.Yellow);
Console.WriteLine($"     {pubStr[..Math.Min(60, pubStr.Length)]}...");

// Protocol: server sends its public key first, then receives client's.
await NetworkHelper.SendStringAsync(stream, pubStr);
Color("[DH] → Public key A sent to client.", ConsoleColor.DarkYellow);

var clientPubStr = await NetworkHelper.ReceiveStringAsync(stream);
var clientPublicKey = BigInteger.Parse(clientPubStr);
Color($"[DH] ← Received Client Public Key B ({clientPubStr.Length} digits):", ConsoleColor.Yellow);
Console.WriteLine($"     {clientPubStr[..Math.Min(60, clientPubStr.Length)]}...");

dh.ComputeSharedSecret(clientPublicKey);
var secretStr = dh.SharedSecret!.Value.ToString();
Color($"[DH] Shared Secret S = B^a mod p  ({secretStr.Length} digits):", ConsoleColor.Yellow);
Console.WriteLine($"     {secretStr[..Math.Min(60, secretStr.Length)]}...");

var aesKey = dh.DeriveAesKey();
Color($"[DH] AES-256 Key = SHA-256(S) : {Convert.ToHexString(aesKey)}", ConsoleColor.Green);
Color("[DH] Key exchange complete!\n", ConsoleColor.Green);

// ── Chat Loop ────────────────────────────────────────────────────────────────
Color("[Server] Chat ready. Type messages and press Enter.\n", ConsoleColor.Cyan);

var cts = new CancellationTokenSource();
var receiveTask = Task.Run(() => ReceiveLoop(stream, aesKey, cts.Token));
var sendTask    = Task.Run(() => SendLoop("SERVER", stream, aesKey, cts.Token));

await Task.WhenAny(receiveTask, sendTask);
cts.Cancel();
Color("\n[Server] Connection closed.", ConsoleColor.Red);

// ── Loop implementations ─────────────────────────────────────────────────────
static async Task ReceiveLoop(NetworkStream s, byte[] key, CancellationToken ct)
{
    try
    {
        while (!ct.IsCancellationRequested)
        {
            var packet = await NetworkHelper.ReceivePacketAsync(s);
            if (packet is null) break;

            var iv     = Convert.FromBase64String(packet.IV);
            var cipher = Convert.FromBase64String(packet.CipherText);
            var hash   = Convert.FromBase64String(packet.Hash);

            Console.WriteLine();
            Color($"┌─ [Primit Criptat] de la {packet.SenderID} @ {packet.Timestamp}", ConsoleColor.DarkCyan);
            Color($"│  IV:         {Convert.ToHexString(iv)}", ConsoleColor.DarkCyan);
            Color($"│  CipherText: {Convert.ToHexString(cipher)}", ConsoleColor.DarkCyan);
            Color($"│  Hash:       {Convert.ToHexString(hash)}", ConsoleColor.DarkCyan);

            if (!CryptoUtils.VerifyHash(iv, cipher, hash))
            {
                Color("└─ [EROARE] Hash SHA-256 invalid — pachet RESPINS!", ConsoleColor.Red);
                continue;
            }

            var plain = CryptoUtils.Decrypt(cipher, key, iv);
            var text  = Encoding.UTF8.GetString(plain);
            Color($"└─ [Primit Decriptat] [{packet.SenderID}]: {text}", ConsoleColor.Green);
            Color("   [Verificat] Hash SHA-256 valid ✓", ConsoleColor.DarkGreen);
        }
    }
    catch (OperationCanceledException) { }
    catch (Exception ex) when (ex is IOException or ObjectDisposedException)
    {
        Color($"[Server] Receive closed: {ex.Message}", ConsoleColor.Red);
    }
}

static async Task SendLoop(string label, NetworkStream s, byte[] key, CancellationToken ct)
{
    try
    {
        while (!ct.IsCancellationRequested)
        {
            var input = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(input) || ct.IsCancellationRequested) continue;

            var plain         = Encoding.UTF8.GetBytes(input);
            var (cipher, iv)  = CryptoUtils.Encrypt(plain, key);
            var hash          = CryptoUtils.ComputeHash(iv, cipher);

            var packet = new SecurePacket
            {
                SenderID   = label,
                Timestamp  = DateTime.Now.ToString("HH:mm:ss"),
                IV         = Convert.ToBase64String(iv),
                CipherText = Convert.ToBase64String(cipher),
                Hash       = Convert.ToBase64String(hash)
            };

            Color($"[Trimis Criptat]  IV: {Convert.ToHexString(iv)}", ConsoleColor.Magenta);
            Color($"                  CT: {Convert.ToHexString(cipher)}", ConsoleColor.Magenta);

            await NetworkHelper.SendPacketAsync(s, packet);
        }
    }
    catch (OperationCanceledException) { }
    catch (Exception ex) when (ex is IOException or ObjectDisposedException)
    {
        Color($"[Server] Send closed: {ex.Message}", ConsoleColor.Red);
    }
}

static void Color(string text, ConsoleColor color)
{
    Console.ForegroundColor = color;
    Console.WriteLine(text);
    Console.ResetColor();
}

static void PrintBanner()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("╔══════════════════════════════════════════════╗");
    Console.WriteLine("║       SecureChat TCP  —  SERVER              ║");
    Console.WriteLine("║  AES-256-CBC + SHA-256 + Diffie-Hellman      ║");
    Console.WriteLine("╚══════════════════════════════════════════════╝");
    Console.ResetColor();
}
