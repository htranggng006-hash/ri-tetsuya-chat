using System;
using System.Numerics;
using System.Security.Cryptography;

namespace SecureChat.Core.Crypto;

public record ElGamalDigitalSignature(BigInteger R, BigInteger S);

/// <summary>
/// ElGamal Digital Signature with SHA-256 (Chapter 3).
/// Provides authenticity, integrity, and non-repudiation.
/// </summary>
public static class ElGamalSignature
{
    /// <summary>
    /// Computes the integer hash h of dataBytes using SHA-256, mapped modulo (p - 1).
    /// </summary>
    public static BigInteger ComputeHash(ReadOnlySpan<byte> dataBytes, BigInteger p)
    {
        byte[] hash = SHA256.HashData(dataBytes);
        BigInteger h = BigIntegerMath.OS2IP(hash);
        BigInteger pMinus1 = p - BigInteger.One;
        h = h % pMinus1;
        if (h <= BigInteger.Zero) h = BigInteger.One;
        return h;
    }

    /// <summary>
    /// Creates an ElGamal digital signature (r, s) on the input data:
    /// 1. h = SHA-256(data) mod (p - 1)
    /// 2. Pick random k in [2, p - 2] with gcd(k, p - 1) == 1
    /// 3. r = g^k mod p
    /// 4. s = k^(-1) * (h - x * r) mod (p - 1)
    /// </summary>
    /// <param name="privateKey">Signer's private key x</param>
    /// <param name="parameters">Group parameters (p, g)</param>
    /// <param name="dataBytes">Data to be signed</param>
    /// <param name="kOverride">Optional k for deterministic verification/testing</param>
    /// <param name="hOverride">Optional h for unit testing exact textbook examples</param>
    public static ElGamalDigitalSignature Sign(
        ElGamalPrivateKey privateKey,
        ElGamalParameters parameters,
        ReadOnlySpan<byte> dataBytes,
        BigInteger? kOverride = null,
        BigInteger? hOverride = null)
    {
        BigInteger p = parameters.P;
        BigInteger g = parameters.G;
        BigInteger x = privateKey.X;
        BigInteger pMinus1 = p - BigInteger.One;

        BigInteger h = hOverride ?? ComputeHash(dataBytes, p);

        while (true)
        {
            BigInteger k = kOverride ?? BigIntegerMath.GenerateRandomCoprime(pMinus1);
            BigInteger kInv = BigIntegerMath.ModInverse(k, pMinus1);

            BigInteger r = BigIntegerMath.ModPow(g, k, p);

            // s = kInv * (h - x * r) mod (p - 1)
            BigInteger diff = h - (x * r);
            BigInteger s = (kInv * diff) % pMinus1;
            if (s < BigInteger.Zero) s += pMinus1;

            if (s.IsZero)
            {
                if (kOverride != null)
                    throw new InvalidOperationException("s resulted in 0 with supplied k.");
                continue; // degenerate s, regenerate k
            }

            return new ElGamalDigitalSignature(r, s);
        }
    }

    /// <summary>
    /// Verifies an ElGamal digital signature (r, s) against the public key (p, g, y) and dataBytes:
    /// Checks:
    /// 1. 0 &lt; r &lt; p and 0 &lt; s &lt; p - 1
    /// 2. g^h mod p == (y^r * r^s) mod p
    /// </summary>
    public static bool Verify(
        ElGamalPublicKey publicKey,
        ReadOnlySpan<byte> dataBytes,
        ElGamalDigitalSignature signature,
        BigInteger? hOverride = null)
    {
        BigInteger p = publicKey.P;
        BigInteger g = publicKey.G;
        BigInteger y = publicKey.Y;
        BigInteger r = signature.R;
        BigInteger s = signature.S;
        BigInteger pMinus1 = p - BigInteger.One;

        // Validity domain checks
        if (r <= BigInteger.Zero || r >= p)
            return false;
        if (s <= BigInteger.Zero || s >= pMinus1)
            return false;

        BigInteger h = hOverride ?? ComputeHash(dataBytes, p);

        // Left side: g^h mod p
        BigInteger lhs = BigIntegerMath.ModPow(g, h, p);

        // Right side: (y^r * r^s) mod p
        BigInteger yr = BigIntegerMath.ModPow(y, r, p);
        BigInteger rs = BigIntegerMath.ModPow(r, s, p);
        BigInteger rhs = (yr * rs) % p;

        return lhs == rhs;
    }
}
