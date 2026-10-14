using System;
using System.Security.Cryptography;

namespace SecureChat.Core.Crypto;

public record AesGcmEncryptionResult(byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>
/// AES-256-GCM authenticated encryption service (Chapter 2).
/// Protects confidentiality, integrity, and authenticity with Additional Authenticated Data (AAD).
/// </summary>
public static class AesGcmCipher
{
    public const int KeySizeBytes = 32;   // 256 bits
    public const int NonceSizeBytes = 12; // 96 bits
    public const int TagSizeBytes = 16;   // 128 bits

    /// <summary>
    /// Generates a cryptographically secure random 256-bit AES key.
    /// </summary>
    public static byte[] GenerateRandomKey()
    {
        byte[] key = new byte[KeySizeBytes];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    /// <summary>
    /// Encrypts plaintext using AES-256-GCM with a freshly generated 12-byte nonce.
    /// </summary>
    public static AesGcmEncryptionResult Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        byte[]? nonceOverride = null)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"AES-256 key must be exactly {KeySizeBytes} bytes.", nameof(key));

        byte[] nonce = nonceOverride ?? new byte[NonceSizeBytes];
        if (nonceOverride == null)
        {
            RandomNumberGenerator.Fill(nonce);
        }
        else if (nonce.Length != NonceSizeBytes)
        {
            throw new ArgumentException($"Nonce must be {NonceSizeBytes} bytes.", nameof(nonceOverride));
        }

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSizeBytes];

        using var aesGcm = new AesGcm(key, TagSizeBytes);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return new AesGcmEncryptionResult(nonce, ciphertext, tag);
    }

    /// <summary>
    /// Decrypts ciphertext and verifies the authentication tag using AES-256-GCM.
    /// Throws CryptographicException if tag or ciphertext was tampered with.
    /// </summary>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"AES-256 key must be exactly {KeySizeBytes} bytes.", nameof(key));
        if (nonce.Length != NonceSizeBytes)
            throw new ArgumentException($"Nonce must be {NonceSizeBytes} bytes.", nameof(nonce));
        if (tag.Length != TagSizeBytes)
            throw new ArgumentException($"Tag must be {TagSizeBytes} bytes.", nameof(tag));

        byte[] plaintext = new byte[ciphertext.Length];
        using var aesGcm = new AesGcm(key, TagSizeBytes);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

        return plaintext;
    }
}
