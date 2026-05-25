using System.Net.Sockets;
using System.Numerics;
using System.Text;
using SecureChatTCP.Common;

Console.OutputEncoding = Encoding.UTF8;
PrintBanner();

var host = args.Length > 0 ? args[0] : "127.0.0.1";
Color($"[Client] Connecting to {host}:8080...", ConsoleColor.Cyan);

using var tcp = new TcpClient();
await tcp.ConnectAsync(host, 8080);
Color("[Client] Connected!\n", ConsoleColor.Green);

using var stream = tcp.GetStream();

// ── Diffie-Hellman Handshake ────────────────────────────────────────────────
Color("[DH] Starting Diffie-Hellman key exchange...", ConsoleColor.Yellow);
Color("[DH] Parameters: p = 2048-bit prime (OpenSSL dhparam), g = 2", ConsoleColor.DarkYellow);

var dh = new DiffieHellman();

// Protocol: client receives server's public key first, then sends its own.
var serverPubStr = await NetworkHelper.ReceiveStringAsync(stream);
var serverPublicKey = BigInteger.Parse(serverPubStr);
Color($"[DH] ← Received Server Public Key A ({serverPubStr.Length} digits):", ConsoleColor.Yellow);
Console.WriteLine($"     {serverPubStr[..Math.Min(60, serverPubStr.Length)]}...");

var pubStr = dh.PublicKey.ToString();
await NetworkHelper.SendStringAsync(stream, pubStr);
Color($"[DH] → Sent Client Public Key B ({pubStr.Length} digits):", ConsoleColor.Yellow);
Console.WriteLine($"     {pubStr[..Math.Min(60, pubStr.Length)]}...");

dh.ComputeSharedSecret(serverPublicKey);
var secretStr = dh.SharedSecret!.Value.ToString();
Color($"[DH] Shared Secret S = A^b mod p  ({secretStr.Length} digits):", ConsoleColor.Yellow);
Console.WriteLine($"     {secretStr[..Math.Min(60, secretStr.Length)]}...");

var aesKey = dh.DeriveAesKey();
Color($"[DH] AES-256 Key = SHA-256(S) : {Convert.ToHexString(aesKey)}", ConsoleColor.Green);
Color("[DH] Key exchange complete!\n", ConsoleColor.Green);

// ── Chat Loop ────────────────────────────────────────────────────────────────
Color("[Client] Chat ready. Type messages and press Enter.\n", ConsoleColor.Cyan);

var cts = new CancellationTokenSource();
var receiveTask = Task.Run(() => ReceiveLoop(stream, aesKey, cts.Token));
var sendTask    = Task.Run(() => SendLoop("CLIENT", stream, aesKey, cts.Token));

await Task.WhenAny(receiveTask, sendTask);
cts.Cancel();
Color("\n[Client] Connection closed.", ConsoleColor.Red);

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
        Color($"[Client] Receive closed: {ex.Message}", ConsoleColor.Red);
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
        Color($"[Client] Send closed: {ex.Message}", ConsoleColor.Red);
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
    Console.WriteLine("║       SecureChat TCP  —  CLIENT              ║");
    Console.WriteLine("║  AES-256-CBC + SHA-256 + Diffie-Hellman      ║");
    Console.WriteLine("╚══════════════════════════════════════════════╝");
    Console.ResetColor();
}
