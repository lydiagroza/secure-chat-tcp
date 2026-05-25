using System.Security.Cryptography;

namespace SecureChatTCP.Common;

public static class CryptoUtils
{
    // Encrypts plainText with AES-256-CBC and a freshly generated random IV.
    // Returns (cipherText, iv).
    public static (byte[] CipherText, byte[] IV) Encrypt(byte[] plainText, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;           // 256-bit key
        aes.GenerateIV();        // fresh 128-bit IV per message
        using var enc = aes.CreateEncryptor();
        var cipher = enc.TransformFinalBlock(plainText, 0, plainText.Length);
        return (cipher, aes.IV);
    }

    // Decrypts AES-256-CBC cipherText using the given key and IV.
    public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(cipherText, 0, cipherText.Length);
    }

    // Computes SHA-256(IV || CipherText) for integrity verification.
    public static byte[] ComputeHash(byte[] iv, byte[] cipherText)
    {
        var combined = new byte[iv.Length + cipherText.Length];
        iv.CopyTo(combined, 0);
        cipherText.CopyTo(combined, iv.Length);
        return SHA256.HashData(combined);
    }

    // Constant-time comparison to prevent timing attacks.
    public static bool VerifyHash(byte[] iv, byte[] cipherText, byte[] expectedHash)
    {
        var computed = ComputeHash(iv, cipherText);
        return CryptographicOperations.FixedTimeEquals(computed, expectedHash);
    }
}
