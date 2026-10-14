using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SecureChat.Core.Crypto;

namespace SecureChat.Core.KeyManagement;

public record ElGamalPublicKeyDto(string P_Hex, string G_Hex, string Y_Hex, int BitLength)
{
    public static ElGamalPublicKeyDto FromKey(ElGamalPublicKey key) =>
        new(key.P.ToPositiveHex(), key.G.ToPositiveHex(), key.Y.ToPositiveHex(), (int)key.P.GetBitLength());

    public ElGamalPublicKey ToKey() =>
        new(BigIntegerMath.ParsePositiveHex(P_Hex),
            BigIntegerMath.ParsePositiveHex(G_Hex),
            BigIntegerMath.ParsePositiveHex(Y_Hex));
}

public record ElGamalPrivateKeyDto(string X_Hex)
{
    public static ElGamalPrivateKeyDto FromKey(ElGamalPrivateKey key) =>
        new(key.X.ToPositiveHex());

    public ElGamalPrivateKey ToKey() =>
        new(BigIntegerMath.ParsePositiveHex(X_Hex));
}

/// <summary>
/// Public identity and public keys of a user (distributed publicly or via server).
/// </summary>
public class UserPublicKeyAnnouncement
{
    public string UserId { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public bool IsActive { get; set; } = true;

    public ElGamalPublicKeyDto EncryptionPublicKey { get; set; } = new("0", "0", "0", 0);
    public ElGamalPublicKeyDto SigningPublicKey { get; set; } = new("0", "0", "0", 0);

    public string EncryptionFingerprint { get; set; } = string.Empty;
    public string SigningFingerprint { get; set; } = string.Empty;
    public string CombinedFingerprint { get; set; } = string.Empty;
    public string AvatarUrl { get; set; } = string.Empty;
}

/// <summary>
/// Encrypted keystore structure stored on disk or exported as backup file (Chapter 5).
/// </summary>
public class EncryptedKeystoreFile
{
    public string FormatVersion { get; set; } = "1.0";
    public string UserId { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public int Iterations { get; set; } = 100_000;
    public string SaltBase64 { get; set; } = string.Empty;
    public string NonceBase64 { get; set; } = string.Empty;
    public string TagBase64 { get; set; } = string.Empty;
    public string EncryptedPayloadBase64 { get; set; } = string.Empty;
}

/// <summary>
/// Full key bundle held securely in client memory containing both private and public keys.
/// </summary>
public class UserKeyBundle
{
    public string UserId { get; set; } = string.Empty;
    public string KeyId { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public bool IsActive { get; set; } = true;

    public ElGamalKeyPair EncryptionKeyPair { get; set; } = null!;
    public ElGamalKeyPair SigningKeyPair { get; set; } = null!;

    public string EncryptionFingerprint => KeyManager.ComputeFingerprint(EncryptionKeyPair.PublicKey);
    public string SigningFingerprint => KeyManager.ComputeFingerprint(SigningKeyPair.PublicKey);
    public string CombinedFingerprint => KeyManager.ComputeCombinedFingerprint(EncryptionKeyPair.PublicKey, SigningKeyPair.PublicKey);

    public UserPublicKeyAnnouncement ToAnnouncement() => new()
    {
        UserId = UserId,
        KeyId = KeyId,
        CreatedAt = CreatedAt,
        IsActive = IsActive,
        EncryptionPublicKey = ElGamalPublicKeyDto.FromKey(EncryptionKeyPair.PublicKey),
        SigningPublicKey = ElGamalPublicKeyDto.FromKey(SigningKeyPair.PublicKey),
        EncryptionFingerprint = EncryptionFingerprint,
        SigningFingerprint = SigningFingerprint,
        CombinedFingerprint = CombinedFingerprint
    };
}
