using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using SecureChat.Core.Crypto;
using SecureChat.Core.KeyManagement;
using SecureChat.Core.Models;
using SecureChat.Server.Hubs;
using SecureChat.Server.Services;

var builder = WebApplication.CreateBuilder(args);

// Cloud / Render Deployment: Bind to PORT if specified by hosting environment
var port = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(port))
{
    builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
}

// Add services
builder.Services.AddSignalR();
builder.Services.AddSingleton<PublicKeyDirectory>();
builder.Services.AddSingleton<MongoDbService>();
builder.Services.AddSingleton<UserAccountStore>();
builder.Services.AddSingleton<OtpService>();
builder.Services.AddSingleton<EmailService>();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials()
              .SetIsOriginAllowed(_ => true);
    });
});

var app = builder.Build();

app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var exceptionHandlerPathFeature = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerPathFeature>();
        var ex = exceptionHandlerPathFeature?.Error;
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "Lỗi máy chủ không mong muốn tại đường dẫn {Path}", context.Request.Path);

        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { error = ex?.Message ?? "Lỗi máy chủ nội bộ" });
    });
});

app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

// SignalR Chat Hub
app.MapHub<ChatHub>("/chathub");

// API: Send OTP to Email
app.MapPost("/api/auth/send-email-otp", async (SendEmailOtpRequest req, OtpService otpService, EmailService emailService, ILogger<Program> logger) =>
{
    try
    {
        string email = req.Email?.Trim() ?? string.Empty;
        string username = req.Username?.Trim() ?? "Người dùng";

        if (string.IsNullOrWhiteSpace(email))
        {
            return Results.BadRequest(new { error = "Vui lòng nhập địa chỉ email nhận mã OTP." });
        }

        if (!email.Contains('@') || !email.Contains('.'))
        {
            return Results.BadRequest(new { error = "Địa chỉ email không hợp lệ. Vui lòng nhập đúng email (ví dụ: name@gmail.com)." });
        }

        var record = otpService.GenerateOtp(email);
        logger.LogInformation("📧 [OTP Service] Đã tạo mã OTP {Code} cho email {Email}", record.Code, email);

        // Send email via EmailService
        var sendResult = await emailService.SendOtpEmailAsync(email, username, record.Code);

        if (!sendResult.Success)
        {
            return Results.BadRequest(new
            {
                error = sendResult.Message,
                devOtp = record.Code,
                provider = emailService.GetConfiguredProvider()
            });
        }

        return Results.Ok(new
        {
            success = true,
            message = sendResult.Message,
            realEmailSent = sendResult.RealEmailSent,
            provider = emailService.GetConfiguredProvider(),
            devOtp = sendResult.RealEmailSent ? null : record.Code,
            expiresInSeconds = (int)(record.ExpiresAt - DateTimeOffset.UtcNow).TotalSeconds
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// API: Verify OTP standalone
app.MapPost("/api/auth/verify-otp", (VerifyOtpRequest req, OtpService otpService) =>
{
    bool valid = otpService.VerifyOtp(req.Target, req.Otp, consume: false);
    return Results.Ok(new { valid });
});

// API: Register New Account with Email OTP
app.MapPost("/api/auth/register", (RegisterRequest req, UserAccountStore accountStore, OtpService otpService) =>
{
    try
    {
        if (string.IsNullOrWhiteSpace(req.Otp))
        {
            return Results.BadRequest(new { error = "Vui lòng nhập mã OTP xác thực (bấm 'Gửi OTP qua Email' để nhận mã)." });
        }

        if (!otpService.VerifyOtpForEmailOrUser(req.Email, req.Username, req.Otp))
        {
            return Results.BadRequest(new { error = "Mã OTP không đúng hoặc đã hết hạn (5 phút)! Vui lòng kiểm tra lại email hoặc bấm 'Gửi lại mã'." });
        }

        var bundle = accountStore.Register(req.Username, req.Password, req.GroupName ?? "rfc2048", req.Email);
        return Results.Ok(new KeyBundleResponse(
            UserId: bundle.UserId,
            KeyId: bundle.KeyId,
            CreatedAt: bundle.CreatedAt,
            IsActive: bundle.IsActive,
            EncryptionPublicKey: ElGamalPublicKeyDto.FromKey(bundle.EncryptionKeyPair.PublicKey),
            EncryptionPrivateKey: ElGamalPrivateKeyDto.FromKey(bundle.EncryptionKeyPair.PrivateKey),
            SigningPublicKey: ElGamalPublicKeyDto.FromKey(bundle.SigningKeyPair.PublicKey),
            SigningPrivateKey: ElGamalPrivateKeyDto.FromKey(bundle.SigningKeyPair.PrivateKey),
            EncryptionFingerprint: bundle.EncryptionFingerprint,
            SigningFingerprint: bundle.SigningFingerprint,
            CombinedFingerprint: bundle.CombinedFingerprint,
            AvatarUrl: string.Empty,
            Friends: accountStore.GetFriends(bundle.UserId)
        ));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// API: Login Existing Account
app.MapPost("/api/auth/login", (LoginRequest req, UserAccountStore accountStore) =>
{
    try
    {
        var bundle = accountStore.Login(req.Username, req.Password);
        return Results.Ok(new KeyBundleResponse(
            UserId: bundle.UserId,
            KeyId: bundle.KeyId,
            CreatedAt: bundle.CreatedAt,
            IsActive: bundle.IsActive,
            EncryptionPublicKey: ElGamalPublicKeyDto.FromKey(bundle.EncryptionKeyPair.PublicKey),
            EncryptionPrivateKey: ElGamalPrivateKeyDto.FromKey(bundle.EncryptionKeyPair.PrivateKey),
            SigningPublicKey: ElGamalPublicKeyDto.FromKey(bundle.SigningKeyPair.PublicKey),
            SigningPrivateKey: ElGamalPrivateKeyDto.FromKey(bundle.SigningKeyPair.PrivateKey),
            EncryptionFingerprint: bundle.EncryptionFingerprint,
            SigningFingerprint: bundle.SigningFingerprint,
            CombinedFingerprint: bundle.CombinedFingerprint,
            AvatarUrl: accountStore.GetAvatar(bundle.UserId),
            Friends: accountStore.GetFriends(bundle.UserId)
        ));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// API: Check username existence
app.MapGet("/api/auth/check-user", (string username, UserAccountStore accountStore) =>
{
    bool exists = accountStore.UserExists(username);
    return Results.Ok(new { exists });
});

// API: Get Public Key Announcement for any registered/online user
app.MapGet("/api/user/keys", (string username, UserAccountStore accountStore, PublicKeyDirectory directory) =>
{
    var connected = directory.GetUser(username);
    if (connected != null) return Results.Ok(connected.Announcement);

    var reg = accountStore.GetAllRegisteredAnnouncements()
        .FirstOrDefault(a => string.Equals(a.UserId, username, StringComparison.OrdinalIgnoreCase));
    if (reg != null) return Results.Ok(reg);

    return Results.NotFound(new { error = $"Không tìm thấy thông tin khóa của '{username}'." });
});

// API: Friends Management
app.MapPost("/api/friends/add", async (FriendActionRequest req, UserAccountStore accountStore, PublicKeyDirectory directory, IHubContext<ChatHub> hubContext) =>
{
    try
    {
        accountStore.AddFriend(req.Username, req.FriendUsername);
        var myFriends = accountStore.GetFriends(req.Username);

        // Notify friend if online
        var friendConn = directory.GetUser(req.FriendUsername);
        if (friendConn != null)
        {
            var theirFriends = accountStore.GetFriends(req.FriendUsername);
            await hubContext.Clients.Client(friendConn.ConnectionId).SendAsync("FriendsUpdated", theirFriends);
        }

        return Results.Ok(new { success = true, friends = myFriends });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/friends/remove", async (FriendActionRequest req, UserAccountStore accountStore, PublicKeyDirectory directory, IHubContext<ChatHub> hubContext) =>
{
    try
    {
        accountStore.RemoveFriend(req.Username, req.FriendUsername);
        var myFriends = accountStore.GetFriends(req.Username);

        // Notify friend if online
        var friendConn = directory.GetUser(req.FriendUsername);
        if (friendConn != null)
        {
            var theirFriends = accountStore.GetFriends(req.FriendUsername);
            await hubContext.Clients.Client(friendConn.ConnectionId).SendAsync("FriendsUpdated", theirFriends);
        }

        return Results.Ok(new { success = true, friends = myFriends });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/friends/list", (string username, UserAccountStore accountStore) =>
{
    var friends = accountStore.GetFriends(username);
    return Results.Ok(new { friends });
});

// API: Update Avatar
app.MapPost("/api/user/update-avatar", async (UpdateAvatarRequest req, UserAccountStore accountStore, PublicKeyDirectory directory, IHubContext<ChatHub> hubContext) =>
{
    try
    {
        accountStore.UpdateAvatar(req.Username, req.AvatarUrl);
        directory.UpdateUserAvatar(req.Username, req.AvatarUrl);
        await hubContext.Clients.All.SendAsync("UserAvatarUpdated", req.Username, req.AvatarUrl);
        return Results.Ok(new { success = true, avatarUrl = req.AvatarUrl });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// API: Generate Key Bundle
app.MapPost("/api/crypto/create-key-bundle", (CreateKeyBundleRequest req) =>
{
    var group = req.GroupName?.ToLowerInvariant() switch
    {
        "rfc3072" => StandardGroups.Rfc3526_3072,
        "toy23" => StandardGroups.ToyGroup23,
        _ => StandardGroups.Rfc3526_2048
    };

    var bundle = KeyManager.CreateKeyBundle(req.UserId, group);

    return Results.Ok(new KeyBundleResponse(
        UserId: bundle.UserId,
        KeyId: bundle.KeyId,
        CreatedAt: bundle.CreatedAt,
        IsActive: bundle.IsActive,
        EncryptionPublicKey: ElGamalPublicKeyDto.FromKey(bundle.EncryptionKeyPair.PublicKey),
        EncryptionPrivateKey: ElGamalPrivateKeyDto.FromKey(bundle.EncryptionKeyPair.PrivateKey),
        SigningPublicKey: ElGamalPublicKeyDto.FromKey(bundle.SigningKeyPair.PublicKey),
        SigningPrivateKey: ElGamalPrivateKeyDto.FromKey(bundle.SigningKeyPair.PrivateKey),
        EncryptionFingerprint: bundle.EncryptionFingerprint,
        SigningFingerprint: bundle.SigningFingerprint,
        CombinedFingerprint: bundle.CombinedFingerprint,
        AvatarUrl: "",
        Friends: new List<string>()
    ));
});

// API: Seal message (ElGamal-AES Hybrid + ElGamal Signature)
app.MapPost("/api/crypto/seal-message", (SealMessageRequest req) =>
{
    try
    {
        var senderEncKeys = new ElGamalKeyPair(req.SenderEncPublicKey.ToKey(), req.SenderEncPrivateKey.ToKey());
        var senderSigKeys = new ElGamalKeyPair(req.SenderSigPublicKey.ToKey(), req.SenderSigPrivateKey.ToKey());
        var recipientEncPk = req.RecipientEncPublicKey.ToKey();

        var outcome = HybridEncryptionService.SealMessage(
            senderId: req.SenderId,
            recipientId: req.RecipientId,
            senderEncKeys: senderEncKeys,
            senderSigKeys: senderSigKeys,
            recipientEncPublicKey: recipientEncPk,
            senderSigFingerprint: req.SenderSigFingerprint,
            senderEncFingerprint: req.SenderEncFingerprint,
            recipientEncFingerprint: req.RecipientEncFingerprint,
            plaintext: req.Plaintext
        );

        return Results.Ok(outcome);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// API: Open message (Verify Signature + ElGamal Unwrap AES Key + AES-GCM Decrypt)
app.MapPost("/api/crypto/open-message", (OpenMessageRequest req) =>
{
    try
    {
        var senderSigPk = req.SenderSigPublicKey.ToKey();
        var myEncSk = req.MyEncPrivateKey.ToKey();
        var modulusP = BigIntegerMath.ParsePositiveHex(req.GroupModulusP_Hex);

        var outcome = HybridEncryptionService.OpenMessage(
            envelope: req.Envelope,
            senderSigPublicKey: senderSigPk,
            myEncPrivateKey: myEncSk,
            groupModulusP: modulusP,
            isSender: req.IsSender
        );

        return Results.Ok(outcome);
    }
    catch (CryptographicException cryptoEx)
    {
        return Results.BadRequest(new { error = cryptoEx.Message, isCryptographicError = true });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// API: Export Encrypted Keystore (PBKDF2 + AES-GCM)
app.MapPost("/api/crypto/export-keystore", (ExportKeystoreRequest req) =>
{
    try
    {
        var bundle = new UserKeyBundle
        {
            UserId = req.UserId,
            KeyId = req.KeyId,
            CreatedAt = req.CreatedAt,
            IsActive = req.IsActive,
            EncryptionKeyPair = new ElGamalKeyPair(req.EncPk.ToKey(), req.EncSk.ToKey()),
            SigningKeyPair = new ElGamalKeyPair(req.SigPk.ToKey(), req.SigSk.ToKey())
        };

        string json = KeyManager.ExportEncryptedKeystore(bundle, req.Passphrase);
        return Results.Ok(new { keystoreJson = json });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// API: Import Encrypted Keystore (PBKDF2 + AES-GCM)
app.MapPost("/api/crypto/import-keystore", (ImportKeystoreRequest req, UserAccountStore accountStore) =>
{
    try
    {
        var bundle = KeyManager.ImportEncryptedKeystore(req.KeystoreJson, req.Passphrase);
        return Results.Ok(new KeyBundleResponse(
            UserId: bundle.UserId,
            KeyId: bundle.KeyId,
            CreatedAt: bundle.CreatedAt,
            IsActive: bundle.IsActive,
            EncryptionPublicKey: ElGamalPublicKeyDto.FromKey(bundle.EncryptionKeyPair.PublicKey),
            EncryptionPrivateKey: ElGamalPrivateKeyDto.FromKey(bundle.EncryptionKeyPair.PrivateKey),
            SigningPublicKey: ElGamalPublicKeyDto.FromKey(bundle.SigningKeyPair.PublicKey),
            SigningPrivateKey: ElGamalPrivateKeyDto.FromKey(bundle.SigningKeyPair.PrivateKey),
            EncryptionFingerprint: bundle.EncryptionFingerprint,
            SigningFingerprint: bundle.SigningFingerprint,
            CombinedFingerprint: bundle.CombinedFingerprint,
            AvatarUrl: accountStore.GetAvatar(bundle.UserId),
            Friends: accountStore.GetFriends(bundle.UserId)
        ));
    }
    catch (CryptographicException cex)
    {
        return Results.BadRequest(new { error = cex.Message });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// API: Educational Step-by-Step Demo Lab
app.MapGet("/api/crypto/theory-demo", (string? mode) =>
{
    if (mode == "signature")
    {
        // Chapter 3 Example: p=23, g=5, x=6, y=8, h=13, k=7
        BigInteger p = 23, g = 5, x = 6, y = 8, h = 13, k = 7;
        BigInteger pMinus1 = 22;
        BigInteger kInv = BigIntegerMath.ModInverse(k, pMinus1); // 19
        BigInteger r = BigIntegerMath.ModPow(g, k, p); // 17
        BigInteger diff = h - (x * r); // -89
        BigInteger s = (kInv * diff) % pMinus1;
        if (s < BigInteger.Zero) s += pMinus1; // 3

        BigInteger lhs = BigIntegerMath.ModPow(g, h, p); // 21
        BigInteger yr = BigIntegerMath.ModPow(y, r, p); // 13
        BigInteger rs = BigIntegerMath.ModPow(r, s, p); // 14
        BigInteger rhs = (yr * rs) % p; // 21

        return Results.Ok(new
        {
            algorithm = "ElGamal Digital Signature with SHA-256 (Chương 3)",
            parameters = new { p = "23", g = "5", x = "6", y = "8", h = "13", k = "7", pMinus1 = "22" },
            steps = new[]
            {
                new { step = 1, desc = "Tính nghịch đảo của k mod (p - 1)", formula = "k^(-1) = 7^(-1) mod 22 = 19", result = kInv.ToString() },
                new { step = 2, desc = "Tính thành phần thứ nhất r", formula = "r = g^k mod p = 5^7 mod 23", result = r.ToString() },
                new { step = 3, desc = "Tính thành phần thứ hai s", formula = "s = k^(-1)*(h - x*r) mod (p - 1) = 19*(13 - 6*17) mod 22", result = s.ToString() },
                new { step = 4, desc = "Tạo chữ ký số", formula = "Signature = (r, s)", result = $"({r}, {s})" },
                new { step = 5, desc = "Kiểm tra vế trái", formula = "g^h mod p = 5^13 mod 23", result = lhs.ToString() },
                new { step = 6, desc = "Kiểm tra vế phải", formula = "y^r * r^s mod p = 8^17 * 17^3 mod 23 = 13 * 14 mod 23", result = rhs.ToString() },
                new { step = 7, desc = "Kết luận kiểm tra", formula = "LHS == RHS", result = (lhs == rhs) ? "HỢP LỆ (21 == 21)" : "KHÔNG HỢP LỆ" }
            }
        });
    }
    else
    {
        // Chapter 1 Example: p=23, g=5, x=6, y=8, m=10, k=3
        BigInteger p = 23, g = 5, x = 6, y = 8, m = 10, k = 3;
        BigInteger c1 = BigIntegerMath.ModPow(g, k, p); // 10
        BigInteger yk = BigIntegerMath.ModPow(y, k, p); // 6
        BigInteger c2 = (m * yk) % p; // 14

        BigInteger s = BigIntegerMath.ModPow(c1, x, p); // 6
        BigInteger sInv = BigIntegerMath.ModInverse(s, p); // 4
        BigInteger decryptedM = (c2 * sInv) % p;

        return Results.Ok(new
        {
            algorithm = "ElGamal Asymmetric Encryption (Chương 1)",
            parameters = new { p = "23", g = "5", x = "6", y = "8", m = "10", k = "3" },
            steps = new[]
            {
                new { step = 1, desc = "Sinh khóa công khai", formula = "y = g^x mod p = 5^6 mod 23", result = y.ToString() },
                new { step = 2, desc = "Mã hóa: Tính c1", formula = "c1 = g^k mod p = 5^3 mod 23", result = c1.ToString() },
                new { step = 3, desc = "Mã hóa: Tính c2", formula = "c2 = m * y^k mod p = 10 * 8^3 mod 23", result = c2.ToString() },
                new { step = 4, desc = "Bản mã tạo thành", formula = "c = (c1, c2)", result = $"({c1}, {c2})" },
                new { step = 5, desc = "Giải mã: Tính khóa dùng chung s", formula = "s = c1^x mod p = 10^6 mod 23", result = s.ToString() },
                new { step = 6, desc = "Giải mã: Tính nghịch đảo s^(-1)", formula = "s^(-1) = 6^(-1) mod 23", result = sInv.ToString() },
                new { step = 7, desc = "Giải mã: Khôi phục bản rõ m", formula = "m = c2 * s^(-1) mod p = 14 * 4 mod 23 = 56 mod 23", result = decryptedM.ToString() }
            }
        });
    }
});

// ==========================================================================
// MONGODB BACKUP & PERSISTENCE ENDPOINTS
// ==========================================================================

// API: Get MongoDB Connection & Backup Status
app.MapGet("/api/mongodb/status", async (MongoDbService mongoService) =>
{
    var status = await mongoService.GetStatusAsync();
    return Results.Ok(status);
});

// API: Configure/Reconnect MongoDB Connection
app.MapPost("/api/mongodb/configure", async (ConfigureMongoRequest req, MongoDbService mongoService, UserAccountStore accountStore) =>
{
    if (string.IsNullOrWhiteSpace(req.ConnectionString))
        return Results.BadRequest(new { error = "Chuỗi kết nối ConnectionString không được để trống." });

    string dbName = string.IsNullOrWhiteSpace(req.DatabaseName) ? "RiTetsuyaDb" : req.DatabaseName;
    bool connected = await mongoService.TryConnectAsync(req.ConnectionString, dbName);

    if (connected)
    {
        await accountStore.SyncWithMongoAsync();
    }

    var status = await mongoService.GetStatusAsync();
    return Results.Ok(status);
});

// API: Get E2EE Encrypted Chat History from MongoDB
app.MapGet("/api/chat/history", async (string user1, string user2, MongoDbService mongoService) =>
{
    if (string.IsNullOrWhiteSpace(user1) || string.IsNullOrWhiteSpace(user2))
        return Results.BadRequest(new { error = "Cần cung cấp user1 và user2." });

    var envelopes = await mongoService.GetConversationMessagesAsync(user1, user2);
    return Results.Ok(envelopes);
});

app.Run();

// DTO records
public record ConfigureMongoRequest(string ConnectionString, string? DatabaseName);
public record CreateKeyBundleRequest(string UserId, string? GroupName);
public record KeyBundleResponse(
    string UserId,
    string KeyId,
    DateTimeOffset CreatedAt,
    bool IsActive,
    ElGamalPublicKeyDto EncryptionPublicKey,
    ElGamalPrivateKeyDto EncryptionPrivateKey,
    ElGamalPublicKeyDto SigningPublicKey,
    ElGamalPrivateKeyDto SigningPrivateKey,
    string EncryptionFingerprint,
    string SigningFingerprint,
    string CombinedFingerprint,
    string AvatarUrl,
    List<string> Friends
);

public record SealMessageRequest(
    string SenderId,
    string RecipientId,
    ElGamalPublicKeyDto SenderEncPublicKey,
    ElGamalPrivateKeyDto SenderEncPrivateKey,
    ElGamalPublicKeyDto SenderSigPublicKey,
    ElGamalPrivateKeyDto SenderSigPrivateKey,
    ElGamalPublicKeyDto RecipientEncPublicKey,
    string SenderSigFingerprint,
    string SenderEncFingerprint,
    string RecipientEncFingerprint,
    string Plaintext
);

public record OpenMessageRequest(
    MessageEnvelope Envelope,
    ElGamalPublicKeyDto SenderSigPublicKey,
    ElGamalPrivateKeyDto MyEncPrivateKey,
    string GroupModulusP_Hex,
    bool IsSender
);

public record ExportKeystoreRequest(
    string UserId,
    string KeyId,
    DateTimeOffset CreatedAt,
    bool IsActive,
    ElGamalPublicKeyDto EncPk,
    ElGamalPrivateKeyDto EncSk,
    ElGamalPublicKeyDto SigPk,
    ElGamalPrivateKeyDto SigSk,
    string Passphrase
);

public record ImportKeystoreRequest(string KeystoreJson, string Passphrase);
public record SendEmailOtpRequest(string Email, string? Username);
public record SendOtpRequest(string Target, string? Type);
public record VerifyOtpRequest(string Target, string Otp);
public record RegisterRequest(string Username, string Password, string? GroupName, string? Email, string? Otp);
public record LoginRequest(string Username, string Password);
public record FriendActionRequest(string Username, string FriendUsername);
public record UpdateAvatarRequest(string Username, string AvatarUrl);
