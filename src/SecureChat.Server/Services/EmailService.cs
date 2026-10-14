using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SecureChat.Server.Services;

public class EmailService
{
    private readonly IConfiguration _config;
    private readonly ILogger<EmailService> _logger;
    private readonly HttpClient _httpClient;

    public EmailService(IConfiguration config, ILogger<EmailService> logger)
    {
        _config = config;
        _logger = logger;
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
    }

    /// <summary>
    /// Checks which email provider API key is configured.
    /// </summary>
    public string GetConfiguredProvider()
    {
        if (!string.IsNullOrEmpty(GetApiKey("RESEND_API_KEY"))) return "Resend";
        if (!string.IsNullOrEmpty(GetApiKey("BREVO_API_KEY"))) return "Brevo";
        if (!string.IsNullOrEmpty(GetApiKey("SENDGRID_API_KEY"))) return "SendGrid";
        if (!string.IsNullOrEmpty(GetApiKey("SMTP_PASS"))) return "SMTP";
        return "None";
    }

    private string? GetApiKey(string keyName)
    {
        return Environment.GetEnvironmentVariable(keyName) 
            ?? _config[keyName] 
            ?? _config[$"Email:{keyName}"];
    }

    /// <summary>
    /// Sends an OTP confirmation email using the configured email API key or SMTP.
    /// </summary>
    public async Task<(bool Success, string Message, bool RealEmailSent)> SendOtpEmailAsync(string toEmail, string username, string otpCode)
    {
        if (string.IsNullOrWhiteSpace(toEmail))
        {
            return (false, "Địa chỉ email không được để trống.", false);
        }

        string provider = GetConfiguredProvider();
        _logger.LogInformation("📧 [EmailService] Đang gửi mã OTP {Otp} tới email {Email} qua nhà cung cấp: {Provider}", otpCode, toEmail, provider);

        string subject = $"[Ri Tetsuya] Mã xác thực OTP của bạn: {otpCode}";
        string htmlBody = GenerateEmailHtml(username, otpCode);

        try
        {
            switch (provider)
            {
                case "Resend":
                    await SendViaResendAsync(toEmail, subject, htmlBody);
                    return (true, $"Mã OTP đã được gửi thành công đến hộp thư '{toEmail}' qua Resend!", true);

                case "Brevo":
                    await SendViaBrevoAsync(toEmail, username, subject, htmlBody);
                    return (true, $"Mã OTP đã được gửi thành công đến hộp thư '{toEmail}' qua Brevo!", true);

                case "SendGrid":
                    await SendViaSendGridAsync(toEmail, subject, htmlBody);
                    return (true, $"Mã OTP đã được gửi thành công đến hộp thư '{toEmail}' qua SendGrid!", true);

                case "SMTP":
                    await SendViaSmtpAsync(toEmail, subject, htmlBody);
                    return (true, $"Mã OTP đã được gửi thành công đến hộp thư '{toEmail}' qua SMTP/Gmail!", true);

                default:
                    // Fallback simulated mode when user hasn't added API key yet
                    _logger.LogWarning("⚠️ [EmailService] Chưa cấu hình API Key email (RESEND_API_KEY / BREVO_API_KEY / SMTP_PASS). Mã OTP mô phỏng: {Otp}", otpCode);
                    return (true, $"Mã OTP 6 số đã được tạo cho '{toEmail}'. (Chưa cấu hình API Key Email, đang dùng mã mô phỏng để đăng ký).", false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ [EmailService] Lỗi khi gửi email tới {Email} qua {Provider}", toEmail, provider);
            // Fallback: don't block registration completely if API key is invalid or rate limited, return dev info
            return (false, $"Lỗi từ dịch vụ gửi email ({provider}): {ex.Message}", false);
        }
    }

    private async Task SendViaResendAsync(string toEmail, string subject, string htmlBody)
    {
        string apiKey = GetApiKey("RESEND_API_KEY")!;
        string fromEmail = GetApiKey("EMAIL_FROM") ?? "Ri Tetsuya Chat <onboarding@resend.dev>";

        var payload = new
        {
            from = fromEmail,
            to = new[] { toEmail },
            subject = subject,
            html = htmlBody
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.resend.com/emails")
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

        var response = await _httpClient.SendAsync(request);
        string responseContent = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Resend API Error ({response.StatusCode}): {responseContent}");
        }
    }

    private async Task SendViaBrevoAsync(string toEmail, string username, string subject, string htmlBody)
    {
        string apiKey = GetApiKey("BREVO_API_KEY")!;
        string senderEmail = GetApiKey("EMAIL_FROM") ?? "noreply@ritetsuya.chat";
        string senderName = "Ri Tetsuya Secure Chat";

        var payload = new
        {
            sender = new { name = senderName, email = senderEmail },
            to = new[] { new { email = toEmail, name = username } },
            subject = subject,
            htmlContent = htmlBody
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.brevo.com/v3/smtp/email")
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        request.Headers.Add("api-key", apiKey);

        var response = await _httpClient.SendAsync(request);
        string responseContent = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Brevo API Error ({response.StatusCode}): {responseContent}");
        }
    }

    private async Task SendViaSendGridAsync(string toEmail, string subject, string htmlBody)
    {
        string apiKey = GetApiKey("SENDGRID_API_KEY")!;
        string fromEmail = GetApiKey("EMAIL_FROM") ?? "noreply@ritetsuya.chat";

        var payload = new
        {
            personalizations = new[]
            {
                new { to = new[] { new { email = toEmail } } }
            },
            from = new { email = fromEmail, name = "Ri Tetsuya Secure Chat" },
            subject = subject,
            content = new[]
            {
                new { type = "text/html", value = htmlBody }
            }
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.sendgrid.com/v3/mail/send")
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

        var response = await _httpClient.SendAsync(request);
        string responseContent = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"SendGrid API Error ({response.StatusCode}): {responseContent}");
        }
    }

    private async Task SendViaSmtpAsync(string toEmail, string subject, string htmlBody)
    {
        string host = GetApiKey("SMTP_HOST") ?? "smtp.gmail.com";
        int port = int.TryParse(GetApiKey("SMTP_PORT"), out int p) ? p : 587;
        string user = GetApiKey("SMTP_USER") ?? "";
        string pass = GetApiKey("SMTP_PASS") ?? "";

        using var client = new SmtpClient(host, port)
        {
            Credentials = new NetworkCredential(user, pass),
            EnableSsl = true
        };

        using var mail = new MailMessage
        {
            From = new MailAddress(user, "Ri Tetsuya Secure Chat"),
            Subject = subject,
            Body = htmlBody,
            IsBodyHtml = true
        };
        mail.To.Add(toEmail);

        await client.SendMailAsync(mail);
    }

    private string GenerateEmailHtml(string username, string otpCode)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0b0e14; color: #e4e6eb; margin: 0; padding: 20px; }}
        .container {{ max-width: 520px; margin: 0 auto; background: #18191a; border-radius: 12px; border: 1px solid #2d88ff; padding: 28px; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }}
        .header {{ text-align: center; border-bottom: 1px solid #3a3b3c; padding-bottom: 18px; margin-bottom: 20px; }}
        .logo-title {{ font-size: 24px; font-weight: 700; color: #0084ff; letter-spacing: 0.5px; }}
        .sub {{ font-size: 13px; color: #b0b3b8; margin-top: 4px; }}
        .otp-box {{ background: linear-gradient(135deg, rgba(0, 132, 255, 0.15), rgba(0, 198, 255, 0.25)); border: 2px dashed #0084ff; border-radius: 10px; padding: 18px; text-align: center; margin: 24px 0; }}
        .otp-code {{ font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #38ef7d; font-family: 'Courier New', Courier, monospace; }}
        .note {{ font-size: 13px; color: #b0b3b8; line-height: 1.5; }}
        .footer {{ text-align: center; margin-top: 24px; padding-top: 16px; border-top: 1px solid #242526; font-size: 11px; color: #72767d; }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <div class=""logo-title"">🛡️ Ri Tetsuya Secure Chat</div>
            <div class=""sub"">Hệ thống nhắn tin mã hóa đầu cuối E2EE ElGamal-AES</div>
        </div>
        <p>Xin chào <strong>{WebUtility.HtmlEncode(username)}</strong>,</p>
        <p>Bạn đang đăng ký tài khoản trên <strong>Ri Tetsuya Chat</strong>. Dưới đây là mã xác thực OTP dùng để kích hoạt tài khoản của bạn:</p>
        
        <div class=""otp-box"">
            <div class=""otp-code"">{otpCode}</div>
        </div>

        <p class=""note"">
            ⏱️ Mã OTP này có hiệu lực trong <strong>5 phút</strong>.<br>
            🔒 Không chia sẻ mã xác thực này cho bất kỳ ai để đảm bảo an toàn cho bộ khóa mật mã cá nhân của bạn.
        </p>

        <div class=""footer"">
            © 2026 Ri Tetsuya E2EE Chat. Tin nhắn được bảo vệ bằng mật mã toán học ElGamal 2048-bit.
        </div>
    </div>
</body>
</html>";
    }
}
