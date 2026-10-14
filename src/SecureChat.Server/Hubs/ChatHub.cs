using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;
using SecureChat.Core.KeyManagement;
using SecureChat.Core.Models;
using SecureChat.Server.Services;

namespace SecureChat.Server.Hubs;

public class ChatHub : Hub
{
    private readonly PublicKeyDirectory _directory;
    private readonly UserAccountStore _accountStore;
    private readonly MongoDbService _mongoDbService;
    private readonly ILogger<ChatHub> _logger;

    public ChatHub(
        PublicKeyDirectory directory,
        UserAccountStore accountStore,
        MongoDbService mongoDbService,
        ILogger<ChatHub> logger)
    {
        _directory = directory;
        _accountStore = accountStore;
        _mongoDbService = mongoDbService;
        _logger = logger;
    }

    public async Task Register(UserPublicKeyAnnouncement announcement)
    {
        _logger.LogInformation("User '{UserId}' registered public keys with fingerprint: {Fp}", announcement.UserId, announcement.CombinedFingerprint);
        _directory.RegisterUser(Context.ConnectionId, announcement);

        // Notify other clients that this user is online
        await Clients.Others.SendAsync("UserJoined", announcement);

        // Send current directory (registered users + active online users)
        var allUsers = new Dictionary<string, UserPublicKeyAnnouncement>(StringComparer.OrdinalIgnoreCase);
        foreach (var reg in _accountStore.GetAllRegisteredAnnouncements()) allUsers[reg.UserId] = reg;
        foreach (var act in _directory.GetAllAnnouncements()) allUsers[act.UserId] = act;

        await Clients.Caller.SendAsync("DirectorySync", allUsers.Values.ToList());
        await Clients.Caller.SendAsync("FriendsUpdated", _accountStore.GetFriends(announcement.UserId));
    }

    public async Task SendEnvelope(MessageEnvelope envelope)
    {
        _logger.LogInformation("Relaying encrypted envelope {MessageId} from {Sender} to {Recipient}",
            envelope.MessageId, envelope.SenderId, envelope.RecipientId);

        var recipient = _directory.GetUser(envelope.RecipientId);
        // Deliver to recipient's connection immediately
        if (recipient != null)
        {
            await Clients.Client(recipient.ConnectionId).SendAsync("ReceiveEnvelope", envelope);
        }

        // Echo back to sender for delivery acknowledgment immediately
        await Clients.Caller.SendAsync("MessageSentAck", envelope);

        // Zero-Knowledge backup to MongoDB: run asynchronously in background so real-time chat is INSTANT
        _ = Task.Run(async () =>
        {
            try
            {
                await _mongoDbService.SaveMessageAsync(envelope);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Lỗi sao lưu tin nhắn nền: {Error}", ex.Message);
            }
        });
    }

    public async Task RotateKeys(UserPublicKeyAnnouncement newAnnouncement)
    {
        _logger.LogInformation("User '{UserId}' rotated keys. New fingerprint: {Fp}",
            newAnnouncement.UserId, newAnnouncement.CombinedFingerprint);

        _directory.RegisterUser(Context.ConnectionId, newAnnouncement);
        await Clients.Others.SendAsync("KeysUpdated", newAnnouncement);
    }

    public async Task RecallMessage(string messageId, string recipientId)
    {
        string? senderId = _directory.GetUserId(Context.ConnectionId);
        _logger.LogInformation("Message {MessageId} recalled by sender {SenderId} for recipient {RecipientId}",
            messageId, senderId, recipientId);

        var recipient = _directory.GetUser(recipientId);
        if (recipient != null)
        {
            await Clients.Client(recipient.ConnectionId).SendAsync("MessageRecalled", messageId, senderId);
        }

        await Clients.Caller.SendAsync("MessageRecalled", messageId, senderId);
    }

    public async Task UpdateAvatar(string avatarUrl)
    {
        string? userId = _directory.GetUserId(Context.ConnectionId);
        if (!string.IsNullOrEmpty(userId))
        {
            _accountStore.UpdateAvatar(userId, avatarUrl);
            _directory.UpdateUserAvatar(userId, avatarUrl);
            await Clients.All.SendAsync("UserAvatarUpdated", userId, avatarUrl);
        }
    }

    public async Task AddFriend(string friendUsername)
    {
        string? userId = _directory.GetUserId(Context.ConnectionId);
        if (!string.IsNullOrEmpty(userId))
        {
            _accountStore.AddFriend(userId, friendUsername);

            var myFriends = _accountStore.GetFriends(userId);
            await Clients.Caller.SendAsync("FriendsUpdated", myFriends);

            var friendUser = _directory.GetUser(friendUsername);
            if (friendUser != null)
            {
                var friendFriends = _accountStore.GetFriends(friendUsername);
                await Clients.Client(friendUser.ConnectionId).SendAsync("FriendsUpdated", friendFriends);
            }
        }
    }

    public async Task RemoveFriend(string friendUsername)
    {
        string? userId = _directory.GetUserId(Context.ConnectionId);
        if (!string.IsNullOrEmpty(userId))
        {
            _accountStore.RemoveFriend(userId, friendUsername);

            var myFriends = _accountStore.GetFriends(userId);
            await Clients.Caller.SendAsync("FriendsUpdated", myFriends);

            var friendUser = _directory.GetUser(friendUsername);
            if (friendUser != null)
            {
                var friendFriends = _accountStore.GetFriends(friendUsername);
                await Clients.Client(friendUser.ConnectionId).SendAsync("FriendsUpdated", friendFriends);
            }
        }
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        _directory.UnregisterUser(Context.ConnectionId, out var removedUserId);
        if (!string.IsNullOrEmpty(removedUserId))
        {
            _logger.LogInformation("User '{UserId}' disconnected", removedUserId);
            await Clients.Others.SendAsync("UserLeft", removedUserId);
        }
        await base.OnDisconnectedAsync(exception);
    }
}
