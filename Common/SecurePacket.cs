namespace SecureChatTCP.Common;

public class SecurePacket
{
    public string SenderID { get; set; } = string.Empty;
    public string Timestamp { get; set; } = string.Empty;
    public string IV { get; set; } = string.Empty;         // Base64-encoded AES IV (16 bytes)
    public string CipherText { get; set; } = string.Empty; // Base64-encoded AES-256-CBC ciphertext
    public string Hash { get; set; } = string.Empty;       // Base64-encoded SHA-256(IV || CipherText)
}
