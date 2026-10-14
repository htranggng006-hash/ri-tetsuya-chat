using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SecureChat.Server.Services;

public class OtpRecord
{
    public string Target { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; } = DateTimeOffset.UtcNow.AddMinutes(5);
    public bool IsUsed { get; set; } = false;
}

public class OtpService
{
    private readonly ConcurrentDictionary<string, OtpRecord> _activeOtps = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Generates a cryptographically random 6-digit OTP code for a given username or email/phone.
    /// Includes a 30-second rate-limit between consecutive OTP requests for the same target.
    /// </summary>
    public OtpRecord GenerateOtp(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
            throw new ArgumentException("Tên tài khoản hoặc email/số điện thoại không được để trống.", nameof(target));

        string key = target.Trim();

        // Rate limit: 30 seconds cooldown
        if (_activeOtps.TryGetValue(key, out var existing))
        {
            var elapsed = DateTimeOffset.UtcNow - existing.CreatedAt;
            if (elapsed.TotalSeconds < 30 && !existing.IsUsed && existing.ExpiresAt > DateTimeOffset.UtcNow)
            {
                int remaining = 30 - (int)elapsed.TotalSeconds;
                throw new InvalidOperationException($"Vui lòng đợi {remaining} giây trước khi yêu cầu mã OTP mới.");
            }
        }

        // Cryptographically secure 6-digit random number (100000 - 999999)
        int codeInt = RandomNumberGenerator.GetInt32(100000, 1000000);
        string code = codeInt.ToString("D6");

        var record = new OtpRecord
        {
            Target = key,
            Code = code,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            IsUsed = false
        };

        _activeOtps[key] = record;
        return record;
    }

    /// <summary>
    /// Verifies the OTP code for a target. If valid, marks the OTP as used.
    /// </summary>
    public bool VerifyOtp(string target, string code, bool consume = true)
    {
        if (string.IsNullOrWhiteSpace(target) || string.IsNullOrWhiteSpace(code))
            return false;

        string key = target.Trim();
        if (!_activeOtps.TryGetValue(key, out var record))
            return false;

        if (record.IsUsed)
            return false;

        if (DateTimeOffset.UtcNow > record.ExpiresAt)
            return false;

        if (string.Equals(record.Code.Trim(), code.Trim(), StringComparison.Ordinal))
        {
            if (consume)
            {
                record.IsUsed = true;
            }
            return true;
        }

        return false;
    }

    /// <summary>
    /// Checks OTP against email or username target.
    /// </summary>
    public bool VerifyOtpForEmailOrUser(string? email, string? username, string code, bool consume = true)
    {
        if (!string.IsNullOrWhiteSpace(email) && VerifyOtp(email, code, consume)) return true;
        if (!string.IsNullOrWhiteSpace(username) && VerifyOtp(username, code, consume)) return true;
        return false;
    }
}
