using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureChat.Core.Crypto;

namespace SecureChat.Core.KeyManagement;

/// <summary>
/// Comprehensive Key Management system (Chapter 5):
/// Key generation, fingerprint computation, password-based encrypted storage (PBKDF2 + AES-GCM),
/// backup, restore, and key rotation.
/// </summary>
public static class KeyManager
{
    public const int Pbkdf2Iterations = 100_000;
    public const int SaltSizeBytes = 32;
    private static readonly byte[] KeystoreAad = Encoding.UTF8.GetBytes("SECURE_CHAT_KEYSTORE_V1");

    /// <summary>
    /// Computes the SHA-256 cryptographic fingerprint of a public key.
    /// Formatted in uppercase hexadecimal pairs with colons (e.g., 4A:12:F8:...).
    /// </summary>
    public static string ComputeFingerprint(ElGamalPublicKey pk)
    {
        string canonical = $"{pk.P:X}|{pk.G:X}|{pk.Y:X}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return FormatFingerprint(hash);
    }

    /// <summary>
    /// Computes the combined fingerprint for both encryption and signing public keys.
    /// </summary>
    public static string ComputeCombinedFingerprint(ElGamalPublicKey encPk, ElGamalPublicKey sigPk)
    {
        string canonical = $"ENC:{encPk.P:X}|{encPk.G:X}|{encPk.Y:X}||SIG:{sigPk.P:X}|{sigPk.G:X}|{sigPk.Y:X}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return FormatFingerprint(hash);
    }

    private static string FormatFingerprint(byte[] hash)
    {
        var sb = new StringBuilder(hash.Length * 3);
        for (int i = 0; i < hash.Length; i++)
        {
            sb.Append(hash[i].ToString("X2"));
            if (i < hash.Length - 1) sb.Append(':');
        }
        return sb.ToString();
    }

    /// <summary>
    /// Generates a new user key bundle with separate encryption and signing key pairs.
    /// </summary>
    public static UserKeyBundle CreateKeyBundle(string userId, ElGamalParameters? parameters = null)
    {
        parameters ??= StandardGroups.Default;

        var encKeyPair = ElGamalEncryption.GenerateKeyPair(parameters);
        var sigKeyPair = ElGamalEncryption.GenerateKeyPair(parameters);

        return new UserKeyBundle
        {
            UserId = userId,
            KeyId = Guid.NewGuid().ToString("N"),
            CreatedAt = DateTimeOffset.UtcNow,
            IsActive = true,
            EncryptionKeyPair = encKeyPair,
            SigningKeyPair = sigKeyPair
        };
    }

    private class RawKeyPayload
    {
        public string UserId { get; set; } = string.Empty;
        public string KeyId { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; }
        public bool IsActive { get; set; }
        public ElGamalPublicKeyDto EncPk { get; set; } = null!;
        public ElGamalPrivateKeyDto EncSk { get; set; } = null!;
        public ElGamalPublicKeyDto SigPk { get; set; } = null!;
        public ElGamalPrivateKeyDto SigSk { get; set; } = null!;
    }

    /// <summary>
    /// Exports the user key bundle into an encrypted JSON string protected by a passphrase.
    /// Uses PBKDF2 (100,000 iterations, 32-byte salt, SHA-256) and AES-256-GCM.
    /// </summary>
    public static string ExportEncryptedKeystore(UserKeyBundle bundle, string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));

        // 1. Prepare raw payload
        var payload = new RawKeyPayload
        {
            UserId = bundle.UserId,
            KeyId = bundle.KeyId,
            CreatedAt = bundle.CreatedAt,
            IsActive = bundle.IsActive,
            EncPk = ElGamalPublicKeyDto.FromKey(bundle.EncryptionKeyPair.PublicKey),
            EncSk = ElGamalPrivateKeyDto.FromKey(bundle.EncryptionKeyPair.PrivateKey),
            SigPk = ElGamalPublicKeyDto.FromKey(bundle.SigningKeyPair.PublicKey),
            SigSk = ElGamalPrivateKeyDto.FromKey(bundle.SigningKeyPair.PrivateKey)
        };
        byte[] payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload);

        // 2. Generate Salt & derive AES-256 key via PBKDF2
        byte[] salt = new byte[SaltSizeBytes];
        RandomNumberGenerator.Fill(salt);

        byte[] derivedKey = Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(passphrase),
            salt: salt,
            iterations: Pbkdf2Iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: AesGcmCipher.KeySizeBytes
        );

        // 3. Encrypt payload with AES-256-GCM
        var gcmResult = AesGcmCipher.Encrypt(derivedKey, payloadBytes, KeystoreAad);

        // 4. Wrap into container
        var fileContainer = new EncryptedKeystoreFile
        {
            FormatVersion = "1.0",
            UserId = bundle.UserId,
            KeyId = bundle.KeyId,
            CreatedAt = bundle.CreatedAt,
            Iterations = Pbkdf2Iterations,
            SaltBase64 = Convert.ToBase64String(salt),
            NonceBase64 = Convert.ToBase64String(gcmResult.Nonce),
            TagBase64 = Convert.ToBase64String(gcmResult.Tag),
            EncryptedPayloadBase64 = Convert.ToBase64String(gcmResult.Ciphertext)
        };

        return JsonSerializer.Serialize(fileContainer, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Imports and decrypts a user key bundle from an encrypted JSON string using the passphrase.
    /// </summary>
    public static UserKeyBundle ImportEncryptedKeystore(string keystoreJson, string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));

        var container = JsonSerializer.Deserialize<EncryptedKeystoreFile>(keystoreJson)
            ?? throw new FormatException("Invalid keystore JSON format.");

        byte[] salt = Convert.FromBase64String(container.SaltBase64);
        byte[] nonce = Convert.FromBase64String(container.NonceBase64);
        byte[] tag = Convert.FromBase64String(container.TagBase64);
        byte[] ciphertext = Convert.FromBase64String(container.EncryptedPayloadBase64);

        // Re-derive key
        byte[] derivedKey = Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(passphrase),
            salt: salt,
            iterations: container.Iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: AesGcmCipher.KeySizeBytes
        );

        // Decrypt payload
        byte[] decryptedBytes;
        try
        {
            decryptedBytes = AesGcmCipher.Decrypt(derivedKey, nonce, ciphertext, tag, KeystoreAad);
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("MẬT KHẨU KHÔNG ĐÚNG HOẶC TỆP KEYSTORE ĐÃ BỊ THAY ĐỔI!");
        }

        var payload = JsonSerializer.Deserialize<RawKeyPayload>(decryptedBytes)
            ?? throw new FormatException("Failed to deserialize decrypted keystore payload.");

        return new UserKeyBundle
        {
            UserId = payload.UserId,
            KeyId = payload.KeyId,
            CreatedAt = payload.CreatedAt,
            IsActive = payload.IsActive,
            EncryptionKeyPair = new ElGamalKeyPair(payload.EncPk.ToKey(), payload.EncSk.ToKey()),
            SigningKeyPair = new ElGamalKeyPair(payload.SigPk.ToKey(), payload.SigSk.ToKey())
        };
    }

    public static void SaveKeystoreToFile(UserKeyBundle bundle, string passphrase, string filePath)
    {
        string json = ExportEncryptedKeystore(bundle, passphrase);
        string? dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllText(filePath, json, Encoding.UTF8);
    }

    public static UserKeyBundle LoadKeystoreFromFile(string filePath, string passphrase)
    {
        string json = File.ReadAllText(filePath, Encoding.UTF8);
        return ImportEncryptedKeystore(json, passphrase);
    }
}
