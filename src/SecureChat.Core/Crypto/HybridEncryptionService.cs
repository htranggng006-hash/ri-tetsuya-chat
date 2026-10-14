using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SecureChat.Core.Models;

namespace SecureChat.Core.Crypto;

/// <summary>
/// Diagnostic tracing of intermediate cryptographic operations for academic/educational review.
/// </summary>
public record CryptoInspection(
    string SessionKeyHex,
    string UValueHex,
    string MValueHex,
    string SenderW_C1,
    string SenderW_C2,
    string RecipientW_C1,
    string RecipientW_C2,
    string NonceHex,
    string TagHex,
    string CiphertextHex,
    string Sha256EnvelopeHex,
    string SignatureRHex,
    string SignatureSHex
);

public record EncryptionOutcome(MessageEnvelope Envelope, CryptoInspection Inspection);

public record DecryptionOutcome(string PlaintextMessage, bool SignatureVerified);

/// <summary>
/// Hybrid Encryption Service combining ElGamal (asymmetric key encapsulation & digital signature)
/// and AES-256-GCM (symmetric authenticated payload encryption) as described in Chapter 2.
/// </summary>
public static class HybridEncryptionService
{
    /// <summary>
    /// Wraps an AES-256 key K into an ElGamal ciphertext W = (c1, c2):
    /// u = OS2IP(K)
    /// m = (u + 1)^2
    /// W = (g^k mod p, m * y^k mod p)
    /// </summary>
    public static (ElGamalCiphertext Ciphertext, BigInteger U, BigInteger M) WrapSessionKey(
        ReadOnlySpan<byte> sessionKey,
        ElGamalPublicKey publicKey,
        BigInteger? kOverride = null)
    {
        if (sessionKey.Length != AesGcmCipher.KeySizeBytes)
            throw new ArgumentException($"Session key must be {AesGcmCipher.KeySizeBytes} bytes.", nameof(sessionKey));

        // u = OS2IP(K)
        BigInteger u = BigIntegerMath.OS2IP(sessionKey);

        // m = (u + 1)^2
        BigInteger uPlus1 = u + BigInteger.One;
        BigInteger m = uPlus1 * uPlus1;

        if (m >= publicKey.P)
            throw new InvalidOperationException($"m (bitlength {m.GetBitLength()}) exceeds prime p (bitlength {publicKey.P.GetBitLength()}). Use a larger group modulus.");

        ElGamalCiphertext ciphertext = ElGamalEncryption.Encrypt(publicKey, m, kOverride);
        return (ciphertext, u, m);
    }

    /// <summary>
    /// Unwraps an ElGamal ciphertext W = (c1, c2) back to the 32-byte AES-256 session key K:
    /// m = c2 * (c1^x)^(-1) mod p
    /// uPlus1 = floor(sqrt(m))
    /// Verify: (uPlus1)^2 == m
    /// u = uPlus1 - 1
    /// K = I2OSP(u, 32)
    /// </summary>
    public static byte[] UnwrapSessionKey(
        ElGamalPrivateKey privateKey,
        BigInteger p,
        ElGamalCiphertext ciphertext)
    {
        BigInteger m = ElGamalEncryption.Decrypt(privateKey, p, ciphertext);

        BigInteger uPlus1 = BigIntegerMath.IntegerSqrt(m);
        if (uPlus1 * uPlus1 != m)
            throw new CryptographicException("Decrypted session key failed quadratic residue verification: m is not an exact square.");

        BigInteger u = uPlus1 - BigInteger.One;
        return BigIntegerMath.I2OSP(u, AesGcmCipher.KeySizeBytes);
    }

    /// <summary>
    /// Constructs a fully authenticated and encrypted MessageEnvelope for sending from A to B:
    /// 1. Generates 256-bit session key K and 12-byte Nonce
    /// 2. Wraps K with B's public key (WB) and with A's public key (WA)
    /// 3. Encrypts plaintext with AES-256-GCM using AAD
    /// 4. Signs envelope with A's signing private key
    /// </summary>
    public static EncryptionOutcome SealMessage(
        string senderId,
        string recipientId,
        ElGamalKeyPair senderEncKeys,
        ElGamalKeyPair senderSigKeys,
        ElGamalPublicKey recipientEncPublicKey,
        string senderSigFingerprint,
        string senderEncFingerprint,
        string recipientEncFingerprint,
        string plaintext)
    {
        // 1. Session key & nonce
        byte[] sessionKey = AesGcmCipher.GenerateRandomKey();

        // 2. Wrap session key for Recipient and Sender
        var (wb, u, m) = WrapSessionKey(sessionKey, recipientEncPublicKey);
        var (wa, _, _) = WrapSessionKey(sessionKey, senderEncKeys.PublicKey);

        // 3. Build envelope structure
        var envelope = new MessageEnvelope
        {
            MessageId = Guid.NewGuid().ToString("N"),
            SenderId = senderId,
            RecipientId = recipientId,
            Timestamp = DateTimeOffset.UtcNow,
            ProtocolVersion = "1.0",
            SenderSigFingerprint = senderSigFingerprint,
            SenderEncFingerprint = senderEncFingerprint,
            RecipientEncFingerprint = recipientEncFingerprint,
            SenderKeyW = EncryptedKeyDto.FromCiphertext(wa),
            RecipientKeyW = EncryptedKeyDto.FromCiphertext(wb)
        };

        // 4. Encrypt message payload with AES-256-GCM using AAD
        byte[] aad = envelope.ComputeCanonicalAad();
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var gcmResult = AesGcmCipher.Encrypt(sessionKey, plaintextBytes, aad);

        envelope.NonceBase64 = Convert.ToBase64String(gcmResult.Nonce);
        envelope.CiphertextBase64 = Convert.ToBase64String(gcmResult.Ciphertext);
        envelope.AuthTagBase64 = Convert.ToBase64String(gcmResult.Tag);

        // 5. Digitally sign the canonical envelope with ElGamal
        byte[] dataToSign = envelope.ComputeDataToSign();
        var sig = ElGamalSignature.Sign(senderSigKeys.PrivateKey, senderSigKeys.PublicKey.Parameters, dataToSign);
        envelope.Signature = SignatureDto.FromSignature(sig);

        // Diagnostic inspection
        byte[] hash = SHA256.HashData(dataToSign);
        var inspection = new CryptoInspection(
            SessionKeyHex: Convert.ToHexString(sessionKey),
            UValueHex: u.ToString("X"),
            MValueHex: m.ToString("X"),
            SenderW_C1: wa.C1.ToString("X"),
            SenderW_C2: wa.C2.ToString("X"),
            RecipientW_C1: wb.C1.ToString("X"),
            RecipientW_C2: wb.C2.ToString("X"),
            NonceHex: Convert.ToHexString(gcmResult.Nonce),
            TagHex: Convert.ToHexString(gcmResult.Tag),
            CiphertextHex: Convert.ToHexString(gcmResult.Ciphertext),
            Sha256EnvelopeHex: Convert.ToHexString(hash),
            SignatureRHex: sig.R.ToString("X"),
            SignatureSHex: sig.S.ToString("X")
        );

        return new EncryptionOutcome(envelope, inspection);
    }

    /// <summary>
    /// Verifies envelope signature and decrypts the encrypted message payload.
    /// Supports decryption by recipient (using RecipientKeyW) or sender (using SenderKeyW).
    /// </summary>
    public static DecryptionOutcome OpenMessage(
        MessageEnvelope envelope,
        ElGamalPublicKey senderSigPublicKey,
        ElGamalPrivateKey myEncPrivateKey,
        BigInteger groupModulusP,
        bool isSender)
    {
        // Step 1: Verify ElGamal Digital Signature
        byte[] dataToSign = envelope.ComputeDataToSign();
        var sig = envelope.Signature.ToSignature();
        bool isSigValid = ElGamalSignature.Verify(senderSigPublicKey, dataToSign, sig);

        if (!isSigValid)
            throw new CryptographicException("CHỮ KÝ SỐ KHÔNG HỢP LỆ! Phong bì dữ liệu đã bị sửa đổi hoặc khóa ký không khớp.");

        // Step 2: Unwrap AES-256 session key
        var wrappedKeyDto = isSender ? envelope.SenderKeyW : envelope.RecipientKeyW;
        var wrappedCiphertext = wrappedKeyDto.ToCiphertext();

        byte[] sessionKey = UnwrapSessionKey(myEncPrivateKey, groupModulusP, wrappedCiphertext);

        // Step 3: Decrypt payload using AES-256-GCM and verify authentication tag with AAD
        byte[] nonce = Convert.FromBase64String(envelope.NonceBase64);
        byte[] ciphertext = Convert.FromBase64String(envelope.CiphertextBase64);
        byte[] tag = Convert.FromBase64String(envelope.AuthTagBase64);
        byte[] aad = envelope.ComputeCanonicalAad();

        byte[] decryptedBytes = AesGcmCipher.Decrypt(sessionKey, nonce, ciphertext, tag, aad);
        string plaintext = Encoding.UTF8.GetString(decryptedBytes);

        return new DecryptionOutcome(plaintext, isSigValid);
    }
}
