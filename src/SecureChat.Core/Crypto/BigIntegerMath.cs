using System;
using System.Numerics;
using System.Security.Cryptography;

namespace SecureChat.Core.Crypto;

/// <summary>
/// Mathematical primitives for ElGamal and BigInteger cryptography:
/// modular exponentiation, modular inverse (extended Euclidean), integer square root,
/// OS2IP/I2OSP conversions, and RFC 3526 standard groups.
/// </summary>
public static class BigIntegerMath
{
    /// <summary>
    /// OS2IP: Octet-String-to-Integer-Primitive (RFC 8017 / PKCS #1).
    /// Converts a byte array (big-endian) into a non-negative BigInteger.
    /// </summary>
    public static BigInteger OS2IP(ReadOnlySpan<byte> octets)
    {
        if (octets.IsEmpty) return BigInteger.Zero;
        return new BigInteger(octets, isUnsigned: true, isBigEndian: true);
    }

    /// <summary>
    /// Safely converts a non-negative BigInteger to an unsigned uppercase hex string.
    /// </summary>
    public static string ToPositiveHex(this BigInteger val)
    {
        if (val.IsZero) return "0";
        byte[] bytes = val.ToByteArray(isUnsigned: true, isBigEndian: true);
        return Convert.ToHexString(bytes);
    }

    /// <summary>
    /// Safely parses an unsigned hex string into a guaranteed non-negative BigInteger.
    /// Prefixes with '0' if necessary so that NumberStyles.HexNumber does not treat the
    /// highest bit (>= 0x80) as a negative two's-complement sign bit.
    /// </summary>
    public static BigInteger ParsePositiveHex(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex)) return BigInteger.Zero;
        hex = hex.Trim();
        if (hex.StartsWith("-", StringComparison.Ordinal))
            throw new ArgumentException("Negative hex string is not allowed.", nameof(hex));
        if (!hex.StartsWith("0", StringComparison.Ordinal))
        {
            hex = "0" + hex;
        }
        return BigInteger.Parse(hex, System.Globalization.NumberStyles.HexNumber);
    }

    /// <summary>
    /// I2OSP: Integer-to-Octet-String-Primitive (RFC 8017 / PKCS #1).
    /// Converts a non-negative BigInteger into a byte array of the specified target length (big-endian),
    /// preserving all leading zero bytes.
    /// </summary>
    public static byte[] I2OSP(BigInteger integer, int targetLength)
    {
        if (integer < BigInteger.Zero)
            throw new ArgumentOutOfRangeException(nameof(integer), "Integer must be non-negative.");

        byte[] raw = integer.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length > targetLength)
            throw new ArgumentException($"Integer is too large ({raw.Length} bytes) to fit in {targetLength} bytes.", nameof(integer));

        if (raw.Length == targetLength)
            return raw;

        byte[] padded = new byte[targetLength];
        Array.Copy(raw, 0, padded, targetLength - raw.Length, raw.Length);
        return padded;
    }

    /// <summary>
    /// Computes the modular inverse of a modulo m using the Extended Euclidean Algorithm:
    /// Returns x such that (a * x) % m == 1, where 1 <= x < m.
    /// </summary>
    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        if (m <= BigInteger.One)
            throw new ArgumentOutOfRangeException(nameof(m), "Modulus must be greater than 1.");

        a = (a % m + m) % m; // Ensure a in [0, m-1]
        if (a == BigInteger.Zero)
            throw new ArithmeticException("Modular inverse does not exist for 0.");

        BigInteger m0 = m;
        BigInteger y = BigInteger.Zero, x = BigInteger.One;

        if (m == BigInteger.One)
            return BigInteger.Zero;

        while (a > BigInteger.One)
        {
            if (m == BigInteger.Zero)
                throw new ArithmeticException("Modular inverse does not exist (inputs are not coprime).");

            BigInteger q = a / m;
            BigInteger t = m;

            m = a % m;
            a = t;
            t = y;

            y = x - q * y;
            x = t;
        }

        if (x < BigInteger.Zero)
            x += m0;

        return x;
    }

    /// <summary>
    /// Computes the floor integer square root floor(sqrt(n)) using Newton's method.
    /// </summary>
    public static BigInteger IntegerSqrt(BigInteger n)
    {
        if (n < BigInteger.Zero)
            throw new ArgumentOutOfRangeException(nameof(n), "Square root of negative number is undefined.");
        if (n.IsZero)
            return BigInteger.Zero;
        if (n < 4)
            return BigInteger.One;

        // Initial estimate based on bit length
        int bitLength = (int)n.GetBitLength();
        BigInteger x = BigInteger.One << ((bitLength + 1) / 2);

        while (true)
        {
            BigInteger y = (x + n / x) >> 1;
            if (y >= x)
                return x;
            x = y;
        }
    }

    /// <summary>
    /// Generates a cryptographically secure uniform random BigInteger in the range [minInclusive, maxExclusive).
    /// </summary>
    public static BigInteger GenerateRandom(BigInteger minInclusive, BigInteger maxExclusive)
    {
        if (minInclusive >= maxExclusive)
            throw new ArgumentException("minInclusive must be less than maxExclusive.");

        BigInteger range = maxExclusive - minInclusive;
        int byteCount = (int)range.GetByteCount(isUnsigned: true);
        if (byteCount == 0) byteCount = 1;

        byte[] buffer = new byte[byteCount];

        while (true)
        {
            RandomNumberGenerator.Fill(buffer);
            BigInteger candidate = new BigInteger(buffer, isUnsigned: true, isBigEndian: true);
            // Rejection sampling for uniform distribution
            if (candidate < range)
            {
                return minInclusive + candidate;
            }
        }
    }

    /// <summary>
    /// Generates a random k in [2, maxExclusive) such that gcd(k, maxExclusive) == 1.
    /// Essential for ElGamal signatures where k must be coprime to (p - 1).
    /// </summary>
    public static BigInteger GenerateRandomCoprime(BigInteger maxExclusive)
    {
        if (maxExclusive <= 2)
            throw new ArgumentOutOfRangeException(nameof(maxExclusive), "Modulus must be > 2.");

        while (true)
        {
            BigInteger k = GenerateRandom(2, maxExclusive);
            if (BigInteger.GreatestCommonDivisor(k, maxExclusive) == BigInteger.One)
            {
                return k;
            }
        }
    }

    /// <summary>
    /// Computes (value ^ exponent) mod modulus using standard BigInteger.ModPow.
    /// </summary>
    public static BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus)
    {
        if (exponent < BigInteger.Zero)
        {
            BigInteger inv = ModInverse(value, modulus);
            return BigInteger.ModPow(inv, -exponent, modulus);
        }
        return BigInteger.ModPow(value, exponent, modulus);
    }
}
