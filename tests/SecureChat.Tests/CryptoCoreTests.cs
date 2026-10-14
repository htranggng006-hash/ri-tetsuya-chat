using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SecureChat.Core.Crypto;
using SecureChat.Core.KeyManagement;
using SecureChat.Core.Models;
using Xunit;

namespace SecureChat.Tests;

public class CryptoCoreTests
{
    [Fact]
    public void Chapter1_ElGamalEncryption_ToyExample_MatchesTheory()
    {
        // Theory example from Chapter 1.4:
        // p = 23, g = 5, x = 6 => y = 5^6 mod 23 = 8
        // m = 10, k = 3
        // c1 = 5^3 mod 23 = 10
        // c2 = 10 * 8^3 mod 23 = 14 => c = (10, 14)
        // Decrypt with x = 6 => m = 10

        var pubKey = new ElGamalPublicKey(23, 5, 8);
        var privKey = new ElGamalPrivateKey(6);

        BigInteger m = 10;
        BigInteger k = 3;

        var ciphertext = ElGamalEncryption.Encrypt(pubKey, m, kOverride: k);

        Assert.Equal(new BigInteger(10), ciphertext.C1);
        Assert.Equal(new BigInteger(14), ciphertext.C2);

        BigInteger decrypted = ElGamalEncryption.Decrypt(privKey, pubKey.P, ciphertext);
        Assert.Equal(m, decrypted);
    }

    [Fact]
    public void Chapter3_ElGamalSignature_ToyExample_MatchesTheory()
    {
        // Theory example from Chapter 3.2.4:
        // p = 23, g = 5, x = 6 => y = 8
        // h = 13, k = 7
        // r = 5^7 mod 23 = 17
        // s = 7^(-1) * (13 - 6*17) mod 22 = 19 * (-89) mod 22 = 3
        // Signature = (17, 3)
        // Verify: 5^13 mod 23 = 21 == 8^17 * 17^3 mod 23 = 21

        var pubKey = new ElGamalPublicKey(23, 5, 8);
        var privKey = new ElGamalPrivateKey(6);
        var parameters = pubKey.Parameters;

        BigInteger h = 13;
        BigInteger k = 7;

        var dummyData = Encoding.UTF8.GetBytes("Xin chao");
        var sig = ElGamalSignature.Sign(privKey, parameters, dummyData, kOverride: k, hOverride: h);

        Assert.Equal(new BigInteger(17), sig.R);
        Assert.Equal(new BigInteger(3), sig.S);

        bool isValid = ElGamalSignature.Verify(pubKey, dummyData, sig, hOverride: h);
        Assert.True(isValid);

        // Tampering test: different h should fail
        bool isInvalid = ElGamalSignature.Verify(pubKey, dummyData, sig, hOverride: 14);
        Assert.False(isInvalid);

        // Tampering test: wrong signature r or s
        var tamperedSig = new ElGamalDigitalSignature(18, 3);
        Assert.False(ElGamalSignature.Verify(pubKey, dummyData, tamperedSig, hOverride: h));
    }

    [Fact]
    public void Aes256Gcm_Roundtrip_And_TamperingDetection()
    {
        byte[] key = AesGcmCipher.GenerateRandomKey();
        byte[] plaintext = Encoding.UTF8.GetBytes("Thực nghiệm mã hóa AES-256-GCM an toàn!");
        byte[] aad = Encoding.UTF8.GetBytes("Message-Metadata-Context-123");

        var result = AesGcmCipher.Encrypt(key, plaintext, aad);

        byte[] decrypted = AesGcmCipher.Decrypt(key, result.Nonce, result.Ciphertext, result.Tag, aad);
        Assert.Equal(plaintext, decrypted);

        // Tamper ciphertext
        byte[] tamperedCiphertext = (byte[])result.Ciphertext.Clone();
        tamperedCiphertext[0] ^= 0xFF;
        Assert.ThrowsAny<CryptographicException>(() =>
            AesGcmCipher.Decrypt(key, result.Nonce, tamperedCiphertext, result.Tag, aad));

        // Tamper AAD
        byte[] tamperedAad = Encoding.UTF8.GetBytes("Message-Metadata-Context-HACKED");
        Assert.ThrowsAny<CryptographicException>(() =>
            AesGcmCipher.Decrypt(key, result.Nonce, result.Ciphertext, result.Tag, tamperedAad));
    }

    [Fact]
    public void HybridSessionKey_WrapAndUnwrap_2048BitGroup()
    {
        var group = StandardGroups.Rfc3526_2048;
        var keyPair = ElGamalEncryption.GenerateKeyPair(group);

        byte[] originalSessionKey = AesGcmCipher.GenerateRandomKey();

        var (ciphertext, u, m) = HybridEncryptionService.WrapSessionKey(originalSessionKey, keyPair.PublicKey);

        // Verify m = (u + 1)^2
        Assert.Equal((u + 1) * (u + 1), m);

        byte[] recoveredKey = HybridEncryptionService.UnwrapSessionKey(keyPair.PrivateKey, group.P, ciphertext);

        Assert.Equal(originalSessionKey, recoveredKey);
    }

    [Fact]
    public void EndToEnd_SecureChat_SealAndOpen_WithTamperTests()
    {
        var group = StandardGroups.Rfc3526_2048;

        // Alice (Sender)
        var aliceEnc = ElGamalEncryption.GenerateKeyPair(group);
        var aliceSig = ElGamalEncryption.GenerateKeyPair(group);
        string aliceEncFp = KeyManager.ComputeFingerprint(aliceEnc.PublicKey);
        string aliceSigFp = KeyManager.ComputeFingerprint(aliceSig.PublicKey);

        // Bob (Recipient)
        var bobEnc = ElGamalEncryption.GenerateKeyPair(group);
        var bobSig = ElGamalEncryption.GenerateKeyPair(group);
        string bobEncFp = KeyManager.ComputeFingerprint(bobEnc.PublicKey);

        string originalMessage = "Xin chào Bình, đề tài mã hóa lai ElGamal-AES hoạt động hoàn hảo!";

        // Alice seals the message
        var outcome = HybridEncryptionService.SealMessage(
            senderId: "Alice",
            recipientId: "Bob",
            senderEncKeys: aliceEnc,
            senderSigKeys: aliceSig,
            recipientEncPublicKey: bobEnc.PublicKey,
            senderSigFingerprint: aliceSigFp,
            senderEncFingerprint: aliceEncFp,
            recipientEncFingerprint: bobEncFp,
            plaintext: originalMessage
        );

        Assert.NotNull(outcome.Envelope);
        Assert.NotNull(outcome.Inspection);

        // Bob receives and opens the message
        var bobOutcome = HybridEncryptionService.OpenMessage(
            envelope: outcome.Envelope,
            senderSigPublicKey: aliceSig.PublicKey,
            myEncPrivateKey: bobEnc.PrivateKey,
            groupModulusP: group.P,
            isSender: false
        );

        Assert.True(bobOutcome.SignatureVerified);
        Assert.Equal(originalMessage, bobOutcome.PlaintextMessage);

        // Alice views her own message in chat history using SenderKeyW
        var aliceOutcome = HybridEncryptionService.OpenMessage(
            envelope: outcome.Envelope,
            senderSigPublicKey: aliceSig.PublicKey,
            myEncPrivateKey: aliceEnc.PrivateKey,
            groupModulusP: group.P,
            isSender: true
        );
        Assert.Equal(originalMessage, aliceOutcome.PlaintextMessage);

        // ATTACK 1: Tamper Ciphertext
        var tamperedEnv1 = new MessageEnvelope
        {
            MessageId = outcome.Envelope.MessageId,
            SenderId = outcome.Envelope.SenderId,
            RecipientId = outcome.Envelope.RecipientId,
            Timestamp = outcome.Envelope.Timestamp,
            ProtocolVersion = outcome.Envelope.ProtocolVersion,
            SenderSigFingerprint = outcome.Envelope.SenderSigFingerprint,
            SenderEncFingerprint = outcome.Envelope.SenderEncFingerprint,
            RecipientEncFingerprint = outcome.Envelope.RecipientEncFingerprint,
            SenderKeyW = outcome.Envelope.SenderKeyW,
            RecipientKeyW = outcome.Envelope.RecipientKeyW,
            NonceBase64 = outcome.Envelope.NonceBase64,
            CiphertextBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("Hacked Content")),
            AuthTagBase64 = outcome.Envelope.AuthTagBase64,
            Signature = outcome.Envelope.Signature
        };

        // When ciphertext is changed without re-signing, signature fails!
        Assert.ThrowsAny<CryptographicException>(() =>
            HybridEncryptionService.OpenMessage(tamperedEnv1, aliceSig.PublicKey, bobEnc.PrivateKey, group.P, isSender: false));

        // ATTACK 2: Tamper Signature (r or s)
        var tamperedEnv2 = new MessageEnvelope
        {
            MessageId = outcome.Envelope.MessageId,
            SenderId = outcome.Envelope.SenderId,
            RecipientId = outcome.Envelope.RecipientId,
            Timestamp = outcome.Envelope.Timestamp,
            ProtocolVersion = outcome.Envelope.ProtocolVersion,
            SenderSigFingerprint = outcome.Envelope.SenderSigFingerprint,
            SenderEncFingerprint = outcome.Envelope.SenderEncFingerprint,
            RecipientEncFingerprint = outcome.Envelope.RecipientEncFingerprint,
            SenderKeyW = outcome.Envelope.SenderKeyW,
            RecipientKeyW = outcome.Envelope.RecipientKeyW,
            NonceBase64 = outcome.Envelope.NonceBase64,
            CiphertextBase64 = outcome.Envelope.CiphertextBase64,
            AuthTagBase64 = outcome.Envelope.AuthTagBase64,
            Signature = new SignatureDto((outcome.Envelope.Signature.ToSignature().R + 1).ToString("X"), outcome.Envelope.Signature.SHex)
        };

        Assert.ThrowsAny<CryptographicException>(() =>
            HybridEncryptionService.OpenMessage(tamperedEnv2, aliceSig.PublicKey, bobEnc.PrivateKey, group.P, isSender: false));
    }

    [Fact]
    public void KeyManager_PasswordProtection_And_Fingerprint()
    {
        var group = StandardGroups.Rfc3526_2048;
        var bundle = KeyManager.CreateKeyBundle("Alice", group);

        string password = "MySuperSecretPassword@2026";
        string encryptedJson = KeyManager.ExportEncryptedKeystore(bundle, password);

        Assert.NotEmpty(encryptedJson);
        Assert.Contains("SaltBase64", encryptedJson);
        Assert.Contains("EncryptedPayloadBase64", encryptedJson);

        // Successful import with correct password
        var importedBundle = KeyManager.ImportEncryptedKeystore(encryptedJson, password);
        Assert.Equal(bundle.UserId, importedBundle.UserId);
        Assert.Equal(bundle.EncryptionKeyPair.PublicKey.Y, importedBundle.EncryptionKeyPair.PublicKey.Y);
        Assert.Equal(bundle.SigningKeyPair.PublicKey.Y, importedBundle.SigningKeyPair.PublicKey.Y);
        Assert.Equal(bundle.EncryptionKeyPair.PrivateKey.X, importedBundle.EncryptionKeyPair.PrivateKey.X);
        Assert.Equal(bundle.SigningKeyPair.PrivateKey.X, importedBundle.SigningKeyPair.PrivateKey.X);

        // Failed import with wrong password
        Assert.ThrowsAny<CryptographicException>(() =>
            KeyManager.ImportEncryptedKeystore(encryptedJson, "WrongPassword!"));
    }

    [Fact]
    public void BigInteger_HexRoundtrip_PositiveCheck()
    {
        var p = StandardGroups.Rfc3526_2048.P;
        string hex = p.ToPositiveHex();
        var parsed = BigIntegerMath.ParsePositiveHex(hex);
        Assert.Equal(p, parsed);

        // High-bit hex strings that standard BigInteger.Parse would treat as negative:
        // "80" as signed hex is -128, but as unsigned hex should be 128
        Assert.Equal(new BigInteger(128), BigIntegerMath.ParsePositiveHex("80"));
        Assert.Equal(new BigInteger(255), BigIntegerMath.ParsePositiveHex("FF"));
        Assert.Equal(new BigInteger(0x8000), BigIntegerMath.ParsePositiveHex("8000"));
        Assert.Equal(new BigInteger(0xFFFFFFFF), BigIntegerMath.ParsePositiveHex("FFFFFFFF"));

        // Roundtrip with ToPositiveHex
        BigInteger largeVal = BigIntegerMath.ParsePositiveHex("DEADBEEFCAFE12348000");
        Assert.Equal(largeVal, BigIntegerMath.ParsePositiveHex(largeVal.ToPositiveHex()));
    }
}
