using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;
using SecureChat.Core.KeyManagement;
using SecureChat.Core.Models;

namespace SecureChat.Server.Services;

/// <summary>
/// MongoDB document representation for an end-to-end encrypted message.
/// ZERO-KNOWLEDGE: Only stores ciphertexts, ephemeral public keys, IVs, auth tags, and digital signatures.
/// Plaintext content is NEVER sent to or stored in MongoDB!
/// </summary>
[BsonIgnoreExtraElements]
public class StoredMessageDocument
{
    [BsonId]
    public string MessageId { get; set; } = string.Empty;

    [BsonElement("senderId")]
    public string SenderId { get; set; } = string.Empty;

    [BsonElement("recipientId")]
    public string RecipientId { get; set; } = string.Empty;

    [BsonElement("timestamp")]
    public DateTimeOffset Timestamp { get; set; }

    [BsonElement("storedAt")]
    public DateTime StoredAt { get; set; } = DateTime.UtcNow;

    [BsonElement("envelope")]
    public MessageEnvelope Envelope { get; set; } = null!;
}

/// <summary>
/// MongoDB document representation for a registered user account,
/// including PBKDF2 password hashes, encrypted keystore JSON, avatar, friends,
/// and public key announcement (Chapter 5).
/// </summary>
[BsonIgnoreExtraElements]
public class UserAccountDocument
{
    [BsonId]
    public string Username { get; set; } = string.Empty;

    [BsonElement("passwordSaltBase64")]
    public string PasswordSaltBase64 { get; set; } = string.Empty;

    [BsonElement("passwordHashBase64")]
    public string PasswordHashBase64 { get; set; } = string.Empty;

    [BsonElement("encryptedKeystoreJson")]
    public string EncryptedKeystoreJson { get; set; } = string.Empty;

    [BsonElement("announcement")]
    public UserPublicKeyAnnouncement Announcement { get; set; } = null!;

    [BsonElement("avatarUrl")]
    public string AvatarUrl { get; set; } = string.Empty;

    [BsonElement("friends")]
    public List<string> Friends { get; set; } = new();

    [BsonElement("createdAt")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    [BsonElement("updatedAt")]
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public record MongoStatusDto(
    bool IsConnected,
    string ConnectionString,
    string DatabaseName,
    long UserCount,
    long MessageCount,
    string? LastError,
    DateTime CheckedAt
);

/// <summary>
/// Production-grade MongoDB backup service for user accounts and encrypted chat history.
/// Supports live connection testing, auto-reconnection, index management,
/// and graceful fallback if MongoDB is not reachable.
/// </summary>
public class MongoDbService
{
    private readonly ILogger<MongoDbService> _logger;
    private readonly IConfiguration _configuration;
    private MongoClient? _client;
    private IMongoDatabase? _database;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);

    public string ConnectionString { get; private set; }
    public string DatabaseName { get; private set; }
    public bool IsConnected { get; private set; }
    public string? LastError { get; private set; }
    public DateTime LastCheckedAt { get; private set; } = DateTime.UtcNow;

    public MongoDbService(IConfiguration configuration, ILogger<MongoDbService> logger)
    {
        _configuration = configuration;
        _logger = logger;

        ConnectionString = _configuration["MONGODB_URI"]
            ?? _configuration["MongoDb:ConnectionString"]
            ?? "mongodb://localhost:27017";
        DatabaseName = _configuration["MONGODB_DATABASE"]
            ?? _configuration["MongoDb:DatabaseName"]
            ?? "RiTetsuyaDb";

        // Initial connection attempt in background so server startup is instantaneous
        _ = Task.Run(async () =>
        {
            await TryConnectAsync(ConnectionString, DatabaseName);
            StartBackgroundReconnectionLoop();
        });
    }

    private IMongoCollection<UserAccountDocument>? UsersCollection =>
        _database?.GetCollection<UserAccountDocument>("users");

    private IMongoCollection<StoredMessageDocument>? MessagesCollection =>
        _database?.GetCollection<StoredMessageDocument>("messages");

    /// <summary>
    /// Attempts to connect to the MongoDB instance and ping the database.
    /// </summary>
    public async Task<bool> TryConnectAsync(string connectionString, string databaseName)
    {
        await _connectionLock.WaitAsync();
        try
        {
            ConnectionString = connectionString;
            DatabaseName = databaseName;
            LastCheckedAt = DateTime.UtcNow;

            _logger.LogInformation("Đang kiểm tra kết nối tới MongoDB: {ConnStr} (DB: {Db})...", ConnectionString, DatabaseName);

            var settings = MongoClientSettings.FromConnectionString(connectionString);
            settings.ServerSelectionTimeout = TimeSpan.FromSeconds(3);
            settings.ConnectTimeout = TimeSpan.FromSeconds(3);

            var client = new MongoClient(settings);
            var database = client.GetDatabase(databaseName);

            // Ping MongoDB with a 3-second timeout
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await database.RunCommandAsync((Command<BsonDocument>)"{ping:1}", cancellationToken: cts.Token);

            _client = client;
            _database = database;
            IsConnected = true;
            LastError = null;

            _logger.LogInformation("✅ Kết nối MongoDB THÀNH CÔNG! Database: '{DbName}'. Tính năng sao lưu người dùng & tin nhắn E2EE đã sẵn sàng.", DatabaseName);

            // Ensure optimized indexes
            await CreateIndexesAsync();

            return true;
        }
        catch (Exception ex)
        {
            IsConnected = false;
            LastError = ex.Message;
            _logger.LogWarning("⚠️ Chưa thể kết nối tới MongoDB ({ConnStr}): {Error}. Ứng dụng sẽ hoạt động ở chế độ bộ nhớ đệm và tự động kết nối lại khi MongoDB sẵn sàng.",
                connectionString, ex.Message);
            return false;
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    private async Task CreateIndexesAsync()
    {
        try
        {
            if (MessagesCollection != null)
            {
                // Index for fast conversation history queries: (SenderId, RecipientId, Timestamp)
                var indexKeys = Builders<StoredMessageDocument>.IndexKeys
                    .Ascending(m => m.SenderId)
                    .Ascending(m => m.RecipientId)
                    .Ascending(m => m.Timestamp);

                await MessagesCollection.Indexes.CreateOneAsync(
                    new CreateIndexModel<StoredMessageDocument>(indexKeys, new CreateIndexOptions { Background = true }));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Tạo index MongoDB: {Message}", ex.Message);
        }
    }

    private void StartBackgroundReconnectionLoop()
    {
        _ = Task.Run(async () =>
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromSeconds(25));
                if (!IsConnected)
                {
                    try
                    {
                        await TryConnectAsync(ConnectionString, DatabaseName);
                    }
                    catch
                    {
                        // Background retry failure is logged in TryConnectAsync
                    }
                }
            }
        });
    }

    // ==========================================================================
    // USER ACCOUNT BACKUP OPERATIONS
    // ==========================================================================

    public async Task SaveUserAsync(UserAccountRecord user)
    {
        if (!IsConnected || UsersCollection == null) return;

        try
        {
            var doc = new UserAccountDocument
            {
                Username = user.Username,
                PasswordSaltBase64 = user.PasswordSaltBase64,
                PasswordHashBase64 = user.PasswordHashBase64,
                EncryptedKeystoreJson = user.EncryptedKeystoreJson,
                Announcement = user.Announcement,
                AvatarUrl = user.AvatarUrl,
                Friends = user.Friends ?? new(),
                CreatedAt = user.CreatedAt,
                UpdatedAt = DateTimeOffset.UtcNow
            };

            await UsersCollection.ReplaceOneAsync(
                u => u.Username == user.Username,
                doc,
                new ReplaceOptions { IsUpsert = true });

            _logger.LogInformation("💾 [MongoDB] Đã sao lưu tài khoản '{Username}' thành công.", user.Username);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Lỗi sao lưu tài khoản sang MongoDB: {Error}", ex.Message);
        }
    }

    public async Task UpdateUserFriendsAsync(string username, List<string> friends)
    {
        if (!IsConnected || UsersCollection == null) return;

        try
        {
            var update = Builders<UserAccountDocument>.Update
                .Set(u => u.Friends, friends)
                .Set(u => u.UpdatedAt, DateTimeOffset.UtcNow);

            await UsersCollection.UpdateOneAsync(u => u.Username == username, update);
            _logger.LogInformation("💾 [MongoDB] Đã cập nhật danh sách bạn bè cho '{Username}'.", username);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Lỗi cập nhật bạn bè trên MongoDB: {Error}", ex.Message);
        }
    }

    public async Task UpdateUserAvatarAsync(string username, string avatarUrl)
    {
        if (!IsConnected || UsersCollection == null) return;

        try
        {
            var update = Builders<UserAccountDocument>.Update
                .Set(u => u.AvatarUrl, avatarUrl)
                .Set(u => u.UpdatedAt, DateTimeOffset.UtcNow);

            await UsersCollection.UpdateOneAsync(u => u.Username == username, update);
            _logger.LogInformation("💾 [MongoDB] Đã cập nhật ảnh đại diện cho '{Username}'.", username);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Lỗi cập nhật avatar trên MongoDB: {Error}", ex.Message);
        }
    }

    public async Task<List<UserAccountRecord>> GetAllUsersAsync()
    {
        if (!IsConnected || UsersCollection == null) return new();

        try
        {
            var docs = await UsersCollection.Find(_ => true).ToListAsync();
            return docs.Select(d => new UserAccountRecord
            {
                Username = d.Username,
                PasswordSaltBase64 = d.PasswordSaltBase64,
                PasswordHashBase64 = d.PasswordHashBase64,
                EncryptedKeystoreJson = d.EncryptedKeystoreJson,
                Announcement = d.Announcement,
                AvatarUrl = d.AvatarUrl,
                Friends = d.Friends ?? new(),
                CreatedAt = d.CreatedAt
            }).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Lỗi nạp danh sách tài khoản từ MongoDB: {Error}", ex.Message);
            return new();
        }
    }

    // ==========================================================================
    // ENCRYPTED MESSAGE BACKUP OPERATIONS
    // ==========================================================================

    public async Task SaveMessageAsync(MessageEnvelope envelope)
    {
        if (!IsConnected || MessagesCollection == null) return;

        try
        {
            var doc = new StoredMessageDocument
            {
                MessageId = envelope.MessageId,
                SenderId = envelope.SenderId,
                RecipientId = envelope.RecipientId,
                Timestamp = envelope.Timestamp,
                StoredAt = DateTime.UtcNow,
                Envelope = envelope
            };

            await MessagesCollection.ReplaceOneAsync(
                m => m.MessageId == envelope.MessageId,
                doc,
                new ReplaceOptions { IsUpsert = true });

            _logger.LogInformation("💾 [MongoDB] Đã sao lưu tin nhắn E2EE {MessageId} ({Sender} -> {Recipient})",
                envelope.MessageId, envelope.SenderId, envelope.RecipientId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Lỗi sao lưu tin nhắn sang MongoDB: {Error}", ex.Message);
        }
    }

    public async Task<List<MessageEnvelope>> GetConversationMessagesAsync(string user1, string user2, int limit = 100)
    {
        if (!IsConnected || MessagesCollection == null) return new();

        try
        {
            // Match messages between user1 and user2 in either direction
            var filter = Builders<StoredMessageDocument>.Filter.Or(
                Builders<StoredMessageDocument>.Filter.And(
                    Builders<StoredMessageDocument>.Filter.Eq(m => m.SenderId, user1),
                    Builders<StoredMessageDocument>.Filter.Eq(m => m.RecipientId, user2)
                ),
                Builders<StoredMessageDocument>.Filter.And(
                    Builders<StoredMessageDocument>.Filter.Eq(m => m.SenderId, user2),
                    Builders<StoredMessageDocument>.Filter.Eq(m => m.RecipientId, user1)
                )
            );

            var docs = await MessagesCollection.Find(filter)
                .SortBy(m => m.Timestamp)
                .Limit(limit)
                .ToListAsync();

            return docs.Select(d => d.Envelope).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Lỗi đọc lịch sử tin nhắn từ MongoDB: {Error}", ex.Message);
            return new();
        }
    }

    // ==========================================================================
    // DIAGNOSTICS & METRICS
    // ==========================================================================

    public async Task<long> GetUserCountAsync()
    {
        if (!IsConnected || UsersCollection == null) return 0;
        try { return await UsersCollection.CountDocumentsAsync(_ => true); }
        catch { return 0; }
    }

    public async Task<long> GetMessageCountAsync()
    {
        if (!IsConnected || MessagesCollection == null) return 0;
        try { return await MessagesCollection.CountDocumentsAsync(_ => true); }
        catch { return 0; }
    }

    public async Task<MongoStatusDto> GetStatusAsync()
    {
        long users = await GetUserCountAsync();
        long messages = await GetMessageCountAsync();

        return new MongoStatusDto(
            IsConnected: IsConnected,
            ConnectionString: ConnectionString,
            DatabaseName: DatabaseName,
            UserCount: users,
            MessageCount: messages,
            LastError: LastError,
            CheckedAt: DateTime.UtcNow
        );
    }
}
