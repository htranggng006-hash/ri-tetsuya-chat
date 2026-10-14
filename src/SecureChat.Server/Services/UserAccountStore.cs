using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureChat.Core.Crypto;
using SecureChat.Core.KeyManagement;

namespace SecureChat.Server.Services;

public class UserAccountRecord
{
    public string Username { get; set; } = string.Empty;
    public string PasswordSaltBase64 { get; set; } = string.Empty;
    public string PasswordHashBase64 { get; set; } = string.Empty;
    public string EncryptedKeystoreJson { get; set; } = string.Empty;
    public UserPublicKeyAnnouncement Announcement { get; set; } = null!;
    public string AvatarUrl { get; set; } = string.Empty;
    public List<string> Friends { get; set; } = new();
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Persistent user account store with secure password hashing (PBKDF2 SHA-256)
/// and encrypted keystore vault storage (Chapter 5).
/// </summary>
public class UserAccountStore
{
    private readonly ConcurrentDictionary<string, UserAccountRecord> _accounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _storageFilePath;
    private readonly object _fileLock = new();
    private readonly MongoDbService? _mongoDbService;

    public UserAccountStore(MongoDbService? mongoDbService = null)
    {
        _mongoDbService = mongoDbService;

        string baseDir = AppContext.BaseDirectory;
        string dataDir = Path.Combine(baseDir, "data");
        if (!Directory.Exists(dataDir)) Directory.CreateDirectory(dataDir);
        _storageFilePath = Path.Combine(dataDir, "users_store.json");

        LoadFromDisk();
        if (_mongoDbService != null)
        {
            _mongoDbService.OnConnected += SyncWithMongoAsync;
        }
        _ = SyncWithMongoAsync();
    }

    public async Task SyncWithMongoAsync()
    {
        if (_mongoDbService == null) return;
        try
        {
            await Task.Delay(1200);
            if (!_mongoDbService.IsConnected) return;

            var mongoUsers = await _mongoDbService.GetAllUsersAsync();
            foreach (var user in mongoUsers)
            {
                if (!_accounts.ContainsKey(user.Username))
                {
                    _accounts[user.Username] = user;
                }
            }

            foreach (var localUser in _accounts.Values)
            {
                await _mongoDbService.SaveUserAsync(localUser);
            }

            SaveToDisk();
        }
        catch
        {
            // Transient sync failure ignored
        }
    }

    private void LoadFromDisk()
    {
        lock (_fileLock)
        {
            if (File.Exists(_storageFilePath))
            {
                try
                {
                    string json = File.ReadAllText(_storageFilePath, Encoding.UTF8);
                    var list = JsonSerializer.Deserialize<List<UserAccountRecord>>(json);
                    if (list != null)
                    {
                        foreach (var acc in list)
                        {
                            _accounts[acc.Username] = acc;
                        }
                    }
                }
                catch
                {
                    // If corrupted or empty, start fresh
                }
            }
        }
    }

    private void SaveToDisk()
    {
        lock (_fileLock)
        {
            try
            {
                var list = _accounts.Values.ToList();
                string json = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_storageFilePath, json, Encoding.UTF8);
            }
            catch
            {
                // Ignore file write errors in transient states
            }
        }
    }

    public bool UserExists(string username) => _accounts.ContainsKey(username);

    public UserKeyBundle Register(string username, string password, string groupName)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Tên đăng nhập không được để trống.", nameof(username));
        if (string.IsNullOrWhiteSpace(password) || password.Length < 6)
            throw new ArgumentException("Mật khẩu phải có độ dài ít nhất 6 ký tự.", nameof(password));

        if (UserExists(username))
            throw new InvalidOperationException($"Tài khoản '{username}' đã tồn tại trong hệ thống. Vui lòng chọn tên khác hoặc đăng nhập.");

        // 1. Password Salt & PBKDF2 hash for authentication
        byte[] salt = new byte[16];
        RandomNumberGenerator.Fill(salt);

        byte[] passwordHash = Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(password),
            salt: salt,
            iterations: 100_000,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 32
        );

        // 2. Determine ElGamal parameters
        var group = groupName?.ToLowerInvariant() switch
        {
            "rfc3072" => StandardGroups.Rfc3526_3072,
            "toy23" => StandardGroups.ToyGroup23,
            _ => StandardGroups.Rfc3526_2048
        };

        // 3. Generate Key Bundle
        var bundle = KeyManager.CreateKeyBundle(username, group);

        // 4. Encrypt Keystore with user's password (PBKDF2 + AES-GCM)
        string encryptedKeystore = KeyManager.ExportEncryptedKeystore(bundle, password);

        // 5. Save Record
        var record = new UserAccountRecord
        {
            Username = username,
            PasswordSaltBase64 = Convert.ToBase64String(salt),
            PasswordHashBase64 = Convert.ToBase64String(passwordHash),
            EncryptedKeystoreJson = encryptedKeystore,
            Announcement = bundle.ToAnnouncement(),
            CreatedAt = DateTimeOffset.UtcNow
        };

        _accounts[username] = record;
        SaveToDisk();
        _ = _mongoDbService?.SaveUserAsync(record);

        return bundle;
    }

    public UserKeyBundle Login(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Tên đăng nhập và mật khẩu không được để trống.");

        if (!_accounts.TryGetValue(username, out var record))
            throw new KeyNotFoundException($"Không tìm thấy tài khoản '{username}'. Vui lòng bấm 'Đăng Ký' nếu chưa có tài khoản.");

        // 1. Verify password hash
        byte[] salt = Convert.FromBase64String(record.PasswordSaltBase64);
        byte[] expectedHash = Convert.FromBase64String(record.PasswordHashBase64);

        byte[] computedHash = Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(password),
            salt: salt,
            iterations: 100_000,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 32
        );

        if (!CryptographicOperations.FixedTimeEquals(expectedHash, computedHash))
            throw new UnauthorizedAccessException("Mật khẩu không chính xác! Vui lòng kiểm tra lại.");

        // 2. Decrypt keystore to unlock private keys
        UserKeyBundle bundle;
        try
        {
            bundle = KeyManager.ImportEncryptedKeystore(record.EncryptedKeystoreJson, password);
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Không thể mở khóa Keystore bằng mật khẩu này.");
        }

        return bundle;
    }

    public void UpdateKeystore(string username, UserKeyBundle newBundle, string password)
    {
        if (_accounts.TryGetValue(username, out var record))
        {
            record.EncryptedKeystoreJson = KeyManager.ExportEncryptedKeystore(newBundle, password);
            var ann = newBundle.ToAnnouncement();
            ann.AvatarUrl = record.AvatarUrl;
            record.Announcement = ann;
            SaveToDisk();
            _ = _mongoDbService?.SaveUserAsync(record);
        }
    }

    public List<string> GetFriends(string username)
    {
        if (_accounts.TryGetValue(username, out var record))
        {
            return record.Friends.ToList();
        }
        return new List<string>();
    }

    public void AddFriend(string username, string friendUsername)
    {
        if (string.Equals(username, friendUsername, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Không thể kết bạn với chính mình.");

        if (!_accounts.ContainsKey(friendUsername))
            throw new KeyNotFoundException($"Tài khoản '{friendUsername}' không tồn tại trong hệ thống.");

        if (_accounts.TryGetValue(username, out var userRecord))
        {
            if (!userRecord.Friends.Contains(friendUsername, StringComparer.OrdinalIgnoreCase))
                userRecord.Friends.Add(friendUsername);
        }

        // Mutual friendship so both sides see each other as friends
        if (_accounts.TryGetValue(friendUsername, out var friendRecord))
        {
            if (!friendRecord.Friends.Contains(username, StringComparer.OrdinalIgnoreCase))
                friendRecord.Friends.Add(username);
        }

        SaveToDisk();
        if (userRecord != null) _ = _mongoDbService?.UpdateUserFriendsAsync(username, userRecord.Friends);
        if (friendRecord != null) _ = _mongoDbService?.UpdateUserFriendsAsync(friendUsername, friendRecord.Friends);
    }

    public void RemoveFriend(string username, string friendUsername)
    {
        if (_accounts.TryGetValue(username, out var userRecord))
        {
            userRecord.Friends.RemoveAll(f => string.Equals(f, friendUsername, StringComparison.OrdinalIgnoreCase));
        }

        if (_accounts.TryGetValue(friendUsername, out var friendRecord))
        {
            friendRecord.Friends.RemoveAll(f => string.Equals(f, username, StringComparison.OrdinalIgnoreCase));
        }

        SaveToDisk();
        if (userRecord != null) _ = _mongoDbService?.UpdateUserFriendsAsync(username, userRecord.Friends);
        if (friendRecord != null) _ = _mongoDbService?.UpdateUserFriendsAsync(friendUsername, friendRecord.Friends);
    }

    public string UpdateAvatar(string username, string avatarUrl)
    {
        if (_accounts.TryGetValue(username, out var record))
        {
            record.AvatarUrl = avatarUrl;
            if (record.Announcement != null)
            {
                record.Announcement.AvatarUrl = avatarUrl;
            }
            SaveToDisk();
            _ = _mongoDbService?.UpdateUserAvatarAsync(username, avatarUrl);
            return avatarUrl;
        }
        throw new KeyNotFoundException($"Không tìm thấy tài khoản '{username}'.");
    }

    public string GetAvatar(string username)
    {
        if (_accounts.TryGetValue(username, out var record))
        {
            return record.AvatarUrl;
        }
        return string.Empty;
    }

    public IEnumerable<UserPublicKeyAnnouncement> GetAllRegisteredAnnouncements()
    {
        return _accounts.Values
            .Where(a => a.Announcement != null)
            .Select(a =>
            {
                a.Announcement!.AvatarUrl = a.AvatarUrl;
                return a.Announcement;
            });
    }
}
