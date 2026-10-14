using System;
using System.Numerics;
using System.Text;
using SecureChat.Core.Crypto;

namespace SecureChat.Core.Models;

public record EncryptedKeyDto(string C1Hex, string C2Hex)
{
    public static EncryptedKeyDto FromCiphertext(ElGamalCiphertext ct) =>
        new(ct.C1.ToPositiveHex(), ct.C2.ToPositiveHex());

    public ElGamalCiphertext ToCiphertext() =>
        new(BigIntegerMath.ParsePositiveHex(C1Hex),
            BigIntegerMath.ParsePositiveHex(C2Hex));
}

public record SignatureDto(string RHex, string SHex)
{
    public static SignatureDto FromSignature(ElGamalDigitalSignature sig) =>
        new(sig.R.ToPositiveHex(), sig.S.ToPositiveHex());

    public ElGamalDigitalSignature ToSignature() =>
        new(BigIntegerMath.ParsePositiveHex(RHex),
            BigIntegerMath.ParsePositiveHex(SHex));
}

/// <summary>
/// Full encrypted message envelope (Chapter 2 & 3).
/// Contains:
/// E = (Metadata/AAD, WA, WB, Nonce, Ciphertext, AuthTag, Signature)
/// </summary>
public class MessageEnvelope
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string SenderId { get; set; } = string.Empty;
    public string RecipientId { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string ProtocolVersion { get; set; } = "1.0";

    // Public Key Fingerprints for cryptographic binding
    public string SenderSigFingerprint { get; set; } = string.Empty;
    public string SenderEncFingerprint { get; set; } = string.Empty;
    public string RecipientEncFingerprint { get; set; } = string.Empty;

    // Dual-wrapped AES session key: WA for Sender, WB for Recipient
    public EncryptedKeyDto SenderKeyW { get; set; } = new("0", "0");
    public EncryptedKeyDto RecipientKeyW { get; set; } = new("0", "0");

    // AES-256-GCM Payload
    public string NonceBase64 { get; set; } = string.Empty;
    public string CiphertextBase64 { get; set; } = string.Empty;
    public string AuthTagBase64 { get; set; } = string.Empty;

    // ElGamal Digital Signature (r, s) on the canonical envelope data
    public SignatureDto Signature { get; set; } = new("0", "0");

    /// <summary>
    /// Computes canonical AAD (Additional Authenticated Data) for AES-256-GCM.
    /// Binds contextual header fields to the symmetric ciphertext tag.
    /// </summary>
    public byte[] ComputeCanonicalAad()
    {
        string aadString = $"{ProtocolVersion}|{MessageId}|{SenderId}|{RecipientId}|" +
                           $"{Timestamp.ToUnixTimeSeconds()}|{SenderSigFingerprint}|{RecipientEncFingerprint}";
        return Encoding.UTF8.GetBytes(aadString);
    }

    /// <summary>
    /// Computes canonical bytes of the entire envelope for ElGamal Digital Signature.
    /// Signs (AAD + WA + WB + Nonce + Ciphertext + Tag). Does not include the signature itself!
    /// </summary>
    public byte[] ComputeDataToSign()
    {
        string data = $"{ProtocolVersion}|{MessageId}|{SenderId}|{RecipientId}|" +
                      $"{Timestamp.ToUnixTimeSeconds()}|{SenderSigFingerprint}|{RecipientEncFingerprint}|" +
                      $"{SenderKeyW.C1Hex}|{SenderKeyW.C2Hex}|{RecipientKeyW.C1Hex}|{RecipientKeyW.C2Hex}|" +
                      $"{NonceBase64}|{CiphertextBase64}|{AuthTagBase64}";
        return Encoding.UTF8.GetBytes(data);
    }
}
