using System;
using System.Numerics;

namespace SecureChat.Core.Crypto;

public record ElGamalPublicKey(BigInteger P, BigInteger G, BigInteger Y)
{
    public ElGamalParameters Parameters => new(P, G, "Group", (int)P.GetBitLength());
}

public record ElGamalPrivateKey(BigInteger X);

public record ElGamalKeyPair(ElGamalPublicKey PublicKey, ElGamalPrivateKey PrivateKey);

public record ElGamalCiphertext(BigInteger C1, BigInteger C2);

/// <summary>
/// ElGamal Public-Key Encryption implementation (Chapter 1).
/// Based on the Discrete Logarithm Problem (DLP).
/// </summary>
public static class ElGamalEncryption
{
    /// <summary>
    /// Generates an ElGamal key pair:
    /// Chooses random private key x in [2, p - 2] and computes y = g^x mod p.
    /// </summary>
    public static ElGamalKeyPair GenerateKeyPair(ElGamalParameters parameters)
    {
        BigInteger p = parameters.P;
        BigInteger g = parameters.G;

        // x in [2, p - 2]
        BigInteger x = BigIntegerMath.GenerateRandom(2, p - 1);
        BigInteger y = BigIntegerMath.ModPow(g, x, p);

        return new ElGamalKeyPair(
            new ElGamalPublicKey(p, g, y),
            new ElGamalPrivateKey(x)
        );
    }

    /// <summary>
    /// Encrypts plaintext message m (0 < m < p) using public key PK = (p, g, y).
    /// Computes c1 = g^k mod p and c2 = (m * y^k) mod p.
    /// </summary>
    /// <param name="publicKey">Recipient's public key (p, g, y)</param>
    /// <param name="m">Message represented as an integer 0 &lt; m &lt; p</param>
    /// <param name="kOverride">Optional deterministic k for testing/verification</param>
    public static ElGamalCiphertext Encrypt(ElGamalPublicKey publicKey, BigInteger m, BigInteger? kOverride = null)
    {
        BigInteger p = publicKey.P;
        BigInteger g = publicKey.G;
        BigInteger y = publicKey.Y;

        if (m <= BigInteger.Zero || m >= p)
            throw new ArgumentOutOfRangeException(nameof(m), $"Plaintext m must satisfy 0 < m < p (m was {m}, p has bit length {p.GetBitLength()}).");

        // Random k in [2, p - 2]
        BigInteger k = kOverride ?? BigIntegerMath.GenerateRandom(2, p - 1);

        BigInteger c1 = BigIntegerMath.ModPow(g, k, p);
        BigInteger yk = BigIntegerMath.ModPow(y, k, p);
        BigInteger c2 = (m * yk) % p;

        return new ElGamalCiphertext(c1, c2);
    }

    /// <summary>
    /// Decrypts ciphertext (c1, c2) using private key x and modulus p:
    /// s = c1^x mod p
    /// sInv = s^(-1) mod p
    /// m = (c2 * sInv) mod p
    /// </summary>
    public static BigInteger Decrypt(ElGamalPrivateKey privateKey, BigInteger p, ElGamalCiphertext ciphertext)
    {
        BigInteger x = privateKey.X;
        BigInteger c1 = ciphertext.C1;
        BigInteger c2 = ciphertext.C2;

        if (c1 <= BigInteger.Zero || c1 >= p || c2 <= BigInteger.Zero || c2 >= p)
            throw new ArgumentException("Ciphertext elements must be within (0, p).", nameof(ciphertext));

        // s = c1^x mod p
        BigInteger s = BigIntegerMath.ModPow(c1, x, p);

        // s^(-1) mod p
        BigInteger sInv = BigIntegerMath.ModInverse(s, p);

        // m = (c2 * s^(-1)) mod p
        BigInteger m = (c2 * sInv) % p;
        if (m < BigInteger.Zero) m += p;

        return m;
    }
}
