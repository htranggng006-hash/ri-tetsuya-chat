using System.Collections.Concurrent;
using SecureChat.Core.KeyManagement;

namespace SecureChat.Server.Services;

public record ConnectedUser(string ConnectionId, UserPublicKeyAnnouncement Announcement);

public class PublicKeyDirectory
{
    private readonly ConcurrentDictionary<string, ConnectedUser> _usersByUserId = new();
    private readonly ConcurrentDictionary<string, string> _userIdByConnectionId = new();

    public void RegisterUser(string connectionId, UserPublicKeyAnnouncement announcement)
    {
        _userIdByConnectionId[connectionId] = announcement.UserId;
        _usersByUserId[announcement.UserId] = new ConnectedUser(connectionId, announcement);
    }

    public void UnregisterUser(string connectionId, out string? removedUserId)
    {
        if (_userIdByConnectionId.TryRemove(connectionId, out removedUserId))
        {
            _usersByUserId.TryRemove(removedUserId, out _);
        }
    }

    public ConnectedUser? GetUser(string userId)
    {
        _usersByUserId.TryGetValue(userId, out var user);
        return user;
    }

    public string? GetUserId(string connectionId)
    {
        _userIdByConnectionId.TryGetValue(connectionId, out var userId);
        return userId;
    }

    public void UpdateUserAvatar(string userId, string avatarUrl)
    {
        if (_usersByUserId.TryGetValue(userId, out var user))
        {
            user.Announcement.AvatarUrl = avatarUrl;
        }
    }

    public IEnumerable<UserPublicKeyAnnouncement> GetAllAnnouncements()
    {
        return _usersByUserId.Values.Select(u => u.Announcement);
    }
}
