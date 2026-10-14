using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Win32;
using SecureChat.Core.Crypto;
using SecureChat.Core.KeyManagement;
using SecureChat.Core.Models;

namespace SecureChat.WpfClient;

public record ChatMessageItem(
    bool IsMe,
    string SenderId,
    string RecipientId,
    string Plaintext,
    MessageEnvelope Envelope,
    CryptoInspection? Inspection,
    bool IsError,
    string? ErrorMessage,
    DateTime Timestamp
);

public partial class MainWindow : Window
{
    private HubConnection? _hubConnection;
    private UserKeyBundle? _myKeys;
    private string _myPassphrase = string.Empty;
    private readonly ObservableCollection<UserPublicKeyAnnouncement> _contacts = new();
    private UserPublicKeyAnnouncement? _selectedRecipient;
    private readonly System.Collections.Generic.List<ChatMessageItem> _messages = new();

    public MainWindow()
    {
        InitializeComponent();
        ListContacts.ItemsSource = _contacts;
    }

    private async void BtnRegister_Click(object sender, RoutedEventArgs e)
    {
        await AuthenticateAndConnectAsync(isRegister: true);
    }

    private async void BtnLogin_Click(object sender, RoutedEventArgs e)
    {
        await AuthenticateAndConnectAsync(isRegister: false);
    }

    private class AuthResponseDto
    {
        public string UserId { get; set; } = string.Empty;
        public string KeyId { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; }
        public bool IsActive { get; set; }
        public ElGamalPublicKeyDto EncryptionPublicKey { get; set; } = null!;
        public ElGamalPrivateKeyDto EncryptionPrivateKey { get; set; } = null!;
        public ElGamalPublicKeyDto SigningPublicKey { get; set; } = null!;
        public ElGamalPrivateKeyDto SigningPrivateKey { get; set; } = null!;
        public string EncryptionFingerprint { get; set; } = string.Empty;
        public string SigningFingerprint { get; set; } = string.Empty;
        public string CombinedFingerprint { get; set; } = string.Empty;
    }

    private async Task AuthenticateAndConnectAsync(bool isRegister)
    {
        string username = TxtUsername.Text.Trim();
        string password = TxtPassword.Password;
        string serverUrl = TxtServerUrl.Text.Trim().TrimEnd('/');

        if (string.IsNullOrWhiteSpace(username))
        {
            MessageBox.Show("Vui lòng nhập tên người dùng!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrWhiteSpace(password))
        {
            MessageBox.Show("Vui lòng nhập mật khẩu!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        BtnRegister.IsEnabled = false;
        BtnLogin.IsEnabled = false;

        string hubUrl = serverUrl.EndsWith("/chathub", StringComparison.OrdinalIgnoreCase)
            ? serverUrl
            : $"{serverUrl}/chathub";
        string apiBase = serverUrl.EndsWith("/chathub", StringComparison.OrdinalIgnoreCase)
            ? serverUrl.Substring(0, serverUrl.Length - 8)
            : serverUrl;

        try
        {
            _myPassphrase = password;

            // 1. Call Auth API on Server
            using var httpClient = new System.Net.Http.HttpClient();
            string endpoint = isRegister ? $"{apiBase}/api/auth/register" : $"{apiBase}/api/auth/login";
            var payload = isRegister 
                ? (object)new { Username = username, Password = password, GroupName = "rfc2048" }
                : (object)new { Username = username, Password = password };

            var jsonContent = new System.Net.Http.StringContent(
                System.Text.Json.JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json"
            );

            var response = await httpClient.PostAsync(endpoint, jsonContent);
            string responseString = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                using var doc = System.Text.Json.JsonDocument.Parse(responseString);
                string errMsg = doc.RootElement.TryGetProperty("error", out var ep) 
                    ? ep.GetString() ?? "Lỗi xác thực." 
                    : responseString;
                throw new Exception(errMsg);
            }

            var authResp = System.Text.Json.JsonSerializer.Deserialize<AuthResponseDto>(responseString, 
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new Exception("Không nhận được dữ liệu phản hồi hợp lệ từ server.");

            _myKeys = new UserKeyBundle
            {
                UserId = authResp.UserId,
                KeyId = authResp.KeyId,
                CreatedAt = authResp.CreatedAt,
                IsActive = authResp.IsActive,
                EncryptionKeyPair = new ElGamalKeyPair(authResp.EncryptionPublicKey.ToKey(), authResp.EncryptionPrivateKey.ToKey()),
                SigningKeyPair = new ElGamalKeyPair(authResp.SigningPublicKey.ToKey(), authResp.SigningPrivateKey.ToKey())
            };

            // 2. Connect to SignalR server
            _hubConnection = new HubConnectionBuilder()
                .WithUrl(hubUrl)
                .WithAutomaticReconnect()
                .Build();

            _hubConnection.On<System.Collections.Generic.IEnumerable<UserPublicKeyAnnouncement>>("DirectorySync", list =>
            {
                Dispatcher.Invoke(() =>
                {
                    _contacts.Clear();
                    foreach (var u in list)
                    {
                        if (u.UserId != _myKeys!.UserId) _contacts.Add(u);
                    }
                });
            });

            _hubConnection.On<UserPublicKeyAnnouncement>("UserJoined", user =>
            {
                Dispatcher.Invoke(() =>
                {
                    if (user.UserId != _myKeys!.UserId)
                    {
                        // Remove existing if any, then add
                        for (int i = 0; i < _contacts.Count; i++)
                        {
                            if (_contacts[i].UserId == user.UserId) { _contacts.RemoveAt(i); break; }
                        }
                        _contacts.Add(user);
                    }
                });
            });

            _hubConnection.On<string>("UserLeft", userId =>
            {
                Dispatcher.Invoke(() =>
                {
                    for (int i = 0; i < _contacts.Count; i++)
                    {
                        if (_contacts[i].UserId == userId) { _contacts.RemoveAt(i); break; }
                    }
                    if (_selectedRecipient?.UserId == userId)
                    {
                        _selectedRecipient = null;
                        TxtCurrentChatWith.Text = "Chưa chọn người nhận";
                    }
                });
            });

            _hubConnection.On<UserPublicKeyAnnouncement>("KeysUpdated", user =>
            {
                Dispatcher.Invoke(() =>
                {
                    for (int i = 0; i < _contacts.Count; i++)
                    {
                        if (_contacts[i].UserId == user.UserId)
                        {
                            _contacts[i] = user;
                            break;
                        }
                    }
                    MessageBox.Show($"Người dùng {user.UserId} vừa cập nhật lại bộ khóa!\nDấu vân tay: {user.CombinedFingerprint}",
                        "Cập Nhật Khóa", MessageBoxButton.OK, MessageBoxImage.Information);
                });
            });

            _hubConnection.On<MessageEnvelope>("ReceiveEnvelope", async envelope =>
            {
                await Dispatcher.InvokeAsync(() => HandleIncomingEnvelope(envelope));
            });

            await _hubConnection.StartAsync();

            // Announce public keys
            await _hubConnection.InvokeAsync("Register", _myKeys!.ToAnnouncement());

            // Switch UI state
            LoginPanel.Visibility = Visibility.Collapsed;
            StatusPanel.Visibility = Visibility.Visible;
            TxtLoggedInUser.Text = _myKeys.UserId;
            TxtMyFingerprint.Text = "FP: " + _myKeys.CombinedFingerprint.Substring(0, 16) + "...";
            TxtMyFingerprint.ToolTip = _myKeys.CombinedFingerprint;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Lỗi kết nối hoặc sinh khóa: {ex.Message}", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            BtnRegister.IsEnabled = true;
            BtnLogin.IsEnabled = true;
        }
    }

    private async void BtnLogout_Click(object sender, RoutedEventArgs e)
    {
        if (_hubConnection != null)
        {
            await _hubConnection.StopAsync();
            await _hubConnection.DisposeAsync();
            _hubConnection = null;
        }

        _myKeys = null;
        _contacts.Clear();
        _messages.Clear();
        PanelMessages.Children.Clear();

        LoginPanel.Visibility = Visibility.Visible;
        StatusPanel.Visibility = Visibility.Collapsed;
        TxtCurrentChatWith.Text = "Chưa chọn người nhận";
    }

    private void ListContacts_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        _selectedRecipient = ListContacts.SelectedItem as UserPublicKeyAnnouncement;
        if (_selectedRecipient != null)
        {
            TxtCurrentChatWith.Text = $"Trò chuyện bảo mật với {_selectedRecipient.UserId}";
            TxtRecipientFp.Text = $"Dấu vân tay khóa: {_selectedRecipient.CombinedFingerprint}";
            RefreshMessagesDisplay();
        }
    }

    private void TxtMessageInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            BtnSendMessage_Click(sender, e);
        }
    }

    private async void BtnSendMessage_Click(object sender, RoutedEventArgs e)
    {
        string text = TxtMessageInput.Text.Trim();
        if (string.IsNullOrEmpty(text)) return;

        if (_selectedRecipient == null || _myKeys == null || _hubConnection == null)
        {
            MessageBox.Show("Vui lòng chọn một người nhận online từ danh sách bên trái!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            // Seal message locally using Hybrid ElGamal-AES + ElGamal Signature
            var recipientEncPk = _selectedRecipient.EncryptionPublicKey.ToKey();
            var outcome = HybridEncryptionService.SealMessage(
                senderId: _myKeys.UserId,
                recipientId: _selectedRecipient.UserId,
                senderEncKeys: _myKeys.EncryptionKeyPair,
                senderSigKeys: _myKeys.SigningKeyPair,
                recipientEncPublicKey: recipientEncPk,
                senderSigFingerprint: _myKeys.SigningFingerprint,
                senderEncFingerprint: _myKeys.EncryptionFingerprint,
                recipientEncFingerprint: _selectedRecipient.EncryptionFingerprint,
                plaintext: text
            );

            var envelope = outcome.Envelope;
            var inspection = outcome.Inspection;

            // Tampering options
            if (RbTamperCipher.IsChecked == true)
            {
                envelope.CiphertextBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("NoiDungBiSuaDoi!"));
            }
            else if (RbTamperSig.IsChecked == true)
            {
                envelope.Signature = new SignatureDto("DEADBEEF" + envelope.Signature.RHex.Substring(8), envelope.Signature.SHex);
            }
            else if (RbTamperAad.IsChecked == true)
            {
                envelope.SenderId = "EveTheAttacker";
            }

            // Send envelope to server
            await _hubConnection.InvokeAsync("SendEnvelope", envelope);

            // Record and display
            var msgItem = new ChatMessageItem(
                IsMe: true,
                SenderId: _myKeys.UserId,
                RecipientId: _selectedRecipient.UserId,
                Plaintext: text,
                Envelope: envelope,
                Inspection: inspection,
                IsError: false,
                ErrorMessage: null,
                Timestamp: DateTime.Now
            );

            _messages.Add(msgItem);
            TxtMessageInput.Clear();
            RefreshMessagesDisplay();
            DisplayInspection(inspection, envelope);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Lỗi mã hóa/gửi: {ex.Message}", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void HandleIncomingEnvelope(MessageEnvelope envelope)
    {
        if (_myKeys == null) return;

        UserPublicKeyAnnouncement? senderContact = null;
        foreach (var c in _contacts)
        {
            if (c.UserId == envelope.SenderId) { senderContact = c; break; }
        }

        string plaintext = string.Empty;
        bool isError = false;
        string? errorMessage = null;

        try
        {
            if (senderContact == null)
                throw new Exception($"Không tìm thấy khóa công khai của người gửi '{envelope.SenderId}'.");

            var senderSigPk = senderContact.SigningPublicKey.ToKey();
            var outcome = HybridEncryptionService.OpenMessage(
                envelope: envelope,
                senderSigPublicKey: senderSigPk,
                myEncPrivateKey: _myKeys.EncryptionKeyPair.PrivateKey,
                groupModulusP: _myKeys.EncryptionKeyPair.PublicKey.P,
                isSender: false
            );

            plaintext = outcome.PlaintextMessage;
        }
        catch (Exception ex)
        {
            isError = true;
            errorMessage = ex.Message;
        }

        var msgItem = new ChatMessageItem(
            IsMe: false,
            SenderId: envelope.SenderId,
            RecipientId: _myKeys.UserId,
            Plaintext: plaintext,
            Envelope: envelope,
            Inspection: null,
            IsError: isError,
            ErrorMessage: errorMessage,
            Timestamp: DateTime.Now
        );

        _messages.Add(msgItem);

        if (_selectedRecipient == null || _selectedRecipient.UserId == envelope.SenderId)
        {
            foreach (var c in _contacts)
            {
                if (c.UserId == envelope.SenderId) { _selectedRecipient = c; break; }
            }
            if (_selectedRecipient != null)
            {
                TxtCurrentChatWith.Text = $"Trò chuyện bảo mật với {_selectedRecipient.UserId}";
                TxtRecipientFp.Text = $"Dấu vân tay khóa: {_selectedRecipient.CombinedFingerprint}";
            }
            RefreshMessagesDisplay();
        }
    }

    private void RefreshMessagesDisplay()
    {
        PanelMessages.Children.Clear();
        if (_selectedRecipient == null || _myKeys == null) return;

        foreach (var m in _messages)
        {
            if ((m.SenderId == _myKeys.UserId && m.RecipientId == _selectedRecipient.UserId) ||
                (m.SenderId == _selectedRecipient.UserId && m.RecipientId == _myKeys.UserId))
            {
                AddMessageBubble(m);
            }
        }
        ScrollMessages.ScrollToEnd();
    }

    private void BtnThumbsUp_Click(object sender, RoutedEventArgs e)
    {
        TxtMessageInput.Text = "👍";
        BtnSendMessage_Click(sender, e);
    }

    private void AddMessageBubble(ChatMessageItem msg)
    {
        var border = new Border
        {
            Padding = new Thickness(12, 9, 12, 9),
            Margin = new Thickness(0, 0, 0, 6),
            MaxWidth = 450,
            HorizontalAlignment = msg.IsMe ? HorizontalAlignment.Right : HorizontalAlignment.Left
        };

        if (msg.IsError)
        {
            border.CornerRadius = new CornerRadius(14);
            border.Background = new SolidColorBrush(Color.FromRgb(59, 17, 17));
            border.BorderBrush = new SolidColorBrush(Color.FromRgb(218, 54, 51));
            border.BorderThickness = new Thickness(1);
        }
        else if (msg.IsMe)
        {
            border.CornerRadius = new CornerRadius(16, 16, 3, 16);
            border.Background = new LinearGradientBrush(
                Color.FromRgb(0, 132, 255),
                Color.FromRgb(123, 44, 191),
                new Point(0, 0),
                new Point(1, 1)
            );
        }
        else
        {
            border.CornerRadius = new CornerRadius(16, 16, 16, 3);
            border.Background = new SolidColorBrush(Color.FromRgb(62, 64, 66));
        }

        var stack = new StackPanel();

        if (msg.IsError)
        {
            stack.Children.Add(new TextBlock
            {
                Text = "🚨 CẢNH BÁO: TẤN CÔNG BỊ PHÁT HIỆN!",
                Foreground = new SolidColorBrush(Color.FromRgb(255, 123, 114)),
                FontWeight = FontWeights.Bold,
                FontSize = 11
            });
            stack.Children.Add(new TextBlock
            {
                Text = msg.ErrorMessage,
                Foreground = new SolidColorBrush(Color.FromRgb(255, 123, 114)),
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 0)
            });
        }
        else
        {
            stack.Children.Add(new TextBlock
            {
                Text = msg.Plaintext,
                Foreground = new SolidColorBrush(Colors.White),
                FontSize = 13,
                TextWrapping = TextWrapping.Wrap
            });
        }

        var footer = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0) };
        footer.Children.Add(new TextBlock
        {
            Text = $"{msg.Timestamp:HH:mm:ss} • E2EE",
            Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
            FontSize = 9,
            Margin = new Thickness(0, 0, 8, 0)
        });

        var btnInspect = new Button
        {
            Content = "🔬 Soi Mật Mã",
            FontSize = 9,
            Padding = new Thickness(4, 1, 4, 1),
            Background = new SolidColorBrush(Color.FromRgb(13, 17, 23)),
            Foreground = new SolidColorBrush(Color.FromRgb(88, 166, 255)),
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand
        };
        btnInspect.Click += (_, _) => DisplayInspection(msg.Inspection, msg.Envelope);
        footer.Children.Add(btnInspect);

        stack.Children.Add(footer);
        border.Child = stack;
        PanelMessages.Children.Add(border);
    }

    private void DisplayInspection(CryptoInspection? inspection, MessageEnvelope env)
    {
        InspSessionKey.Text = $"Key: {(inspection != null ? inspection.SessionKeyHex : "[Bảo mật E2EE]")}";
        InspU.Text = $"u = OS2IP(K): {(inspection != null ? inspection.UValueHex : "--")}";
        InspM.Text = $"m = (u+1)²: {(inspection != null ? inspection.MValueHex : "--")}";

        InspWb.Text = $"c1={env.RecipientKeyW.C1Hex.Substring(0, Math.Min(24, env.RecipientKeyW.C1Hex.Length))}...\nc2={env.RecipientKeyW.C2Hex.Substring(0, Math.Min(24, env.RecipientKeyW.C2Hex.Length))}...";
        InspWa.Text = $"c1={env.SenderKeyW.C1Hex.Substring(0, Math.Min(24, env.SenderKeyW.C1Hex.Length))}...\nc2={env.SenderKeyW.C2Hex.Substring(0, Math.Min(24, env.SenderKeyW.C2Hex.Length))}...";

        InspNonce.Text = $"Nonce: {env.NonceBase64}";
        InspTag.Text = $"Tag: {env.AuthTagBase64}";
        InspCipher.Text = $"Cipher: {env.CiphertextBase64}";

        InspSigHash.Text = $"Hash: {env.ComputeDataToSign().Length} bytes";
        InspSigR.Text = $"r: {env.Signature.RHex.Substring(0, Math.Min(24, env.Signature.RHex.Length))}...";
        InspSigS.Text = $"s: {env.Signature.SHex.Substring(0, Math.Min(24, env.Signature.SHex.Length))}...";
        InspSigStatus.Text = "Kiểm tra: g^h ≡ y^r • r^s mod p ✔️";
    }

    private async void BtnRotateKeys_Click(object sender, RoutedEventArgs e)
    {
        if (_myKeys == null || _hubConnection == null) return;

        if (MessageBox.Show("Bạn có muốn THU HỒI bộ khóa cũ và tạo BỘ KHÓA MỚI (Key Rotation)?", "Xác nhận", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            _myKeys = KeyManager.CreateKeyBundle(_myKeys.UserId, StandardGroups.Rfc3526_2048);
            await _hubConnection.InvokeAsync("RotateKeys", _myKeys.ToAnnouncement());

            TxtMyFingerprint.Text = "FP: " + _myKeys.CombinedFingerprint.Substring(0, 16) + "...";
            TxtMyFingerprint.ToolTip = _myKeys.CombinedFingerprint;

            MessageBox.Show("Đã sinh bộ khóa mới và thông báo đến toàn bộ các máy khác trong mạng!", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void BtnExportKeystore_Click(object sender, RoutedEventArgs e)
    {
        if (_myKeys == null)
        {
            MessageBox.Show("Vui lòng đăng nhập trước khi xuất Keystore!", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var saveDialog = new SaveFileDialog
        {
            Filter = "Keystore JSON (*.json)|*.json",
            FileName = $"{_myKeys.UserId}_keystore.json"
        };

        if (saveDialog.ShowDialog() == true)
        {
            KeyManager.SaveKeystoreToFile(_myKeys, _myPassphrase, saveDialog.FileName);
            MessageBox.Show("Đã sao lưu Keystore được mã hóa an toàn bằng PBKDF2 + AES-GCM!", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void BtnImportKeystore_Click(object sender, RoutedEventArgs e)
    {
        var openDialog = new OpenFileDialog
        {
            Filter = "Keystore JSON (*.json)|*.json"
        };

        if (openDialog.ShowDialog() == true)
        {
            string password = TxtPassword.Password;
            try
            {
                _myKeys = KeyManager.LoadKeystoreFromFile(openDialog.FileName, password);
                _myPassphrase = password;
                TxtUsername.Text = _myKeys.UserId;
                MessageBox.Show($"Khôi phục thành công Keystore cho người dùng '{_myKeys.UserId}'!\nDấu vân tay: {_myKeys.CombinedFingerprint}", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi khôi phục Keystore: {ex.Message}", "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}