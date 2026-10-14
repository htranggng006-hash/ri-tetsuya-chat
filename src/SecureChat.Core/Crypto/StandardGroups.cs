using System.Numerics;

namespace SecureChat.Core.Crypto;

/// <summary>
/// Domain parameters (p, g) for ElGamal cryptographic operations.
/// </summary>
public record ElGamalParameters(BigInteger P, BigInteger G, string Name, int BitLength)
{
    public override string ToString() => $"{Name} ({BitLength}-bit)";
}

/// <summary>
/// Well-known and standardized MODP Diffie-Hellman/ElGamal groups (RFC 3526)
/// as well as educational toy groups for demonstration and testing.
/// </summary>
public static class StandardGroups
{
    /// <summary>
    /// Educational / Toy group (p = 23, g = 5) matching the step-by-step examples
    /// from Chapter 1 (Encryption/Decryption) and Chapter 3 (Digital Signature) of the project notes.
    /// </summary>
    public static readonly ElGamalParameters ToyGroup23 = new(
        P: 23,
        G: 5,
        Name: "Educational Toy Group",
        BitLength: 5
    );

    /// <summary>
    /// RFC 3526 MODP 2048-bit Group (Group 14).
    /// Safe prime p = 2q + 1, generator g = 2.
    /// Recommended for balance of speed and modern cryptographic strength.
    /// </summary>
    public static readonly ElGamalParameters Rfc3526_2048 = new(
        P: BigInteger.Parse(
            "00" + // Ensure positive BigInteger
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
            System.Globalization.NumberStyles.HexNumber),
        G: 2,
        Name: "RFC 3526 MODP 2048-bit (Group 14)",
        BitLength: 2048
    );

    /// <summary>
    /// RFC 3526 MODP 3072-bit Group (Group 15).
    /// Used for 128-bit security level as mentioned in Chapter 2 notes.
    /// </summary>
    public static readonly ElGamalParameters Rfc3526_3072 = new(
        P: BigInteger.Parse(
            "00" +
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
            "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
            "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
            "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
            "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
            "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
            "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
            "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
            "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
            "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
            "FFFFFFFFFFFFFFFF",
            System.Globalization.NumberStyles.HexNumber),
        G: 2,
        Name: "RFC 3526 MODP 3072-bit (Group 15)",
        BitLength: 3072
    );

    /// <summary>
    /// Default standard group used by the chat application: RFC 3526 2048-bit.
    /// Fast in real-time execution while mathematically fully compliant and secure.
    /// </summary>
    public static ElGamalParameters Default => Rfc3526_2048;
}
