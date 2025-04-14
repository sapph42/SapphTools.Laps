using System;
using System.Globalization;

#nullable enable
namespace SapphTools.Laps.Internal;
internal readonly struct EncryptedInner {
    public string AccountName { get; }
    public string Password { get; }
    public DateTime PasswordUpdateTimestampUTC { get; }

    public static EncryptedInner ParseFromJson(string passwordJson) {
        EncryptedRaw? encryptedRaw =
            EncryptedRaw.Parse(passwordJson) ??
            throw new ArgumentException("Failed to parse JSON.");
        if (string.IsNullOrEmpty(encryptedRaw.AccountName)) {
            throw new ArgumentException("AccountName field was missing from encrypted attribute");
        }
        if (string.IsNullOrEmpty(encryptedRaw.UpdateTimestamp)) {
            throw new ArgumentException("UpdateTimestamp field was missing from encrypted attribute");
        }
        if (string.IsNullOrEmpty(encryptedRaw.Password)) {
            throw new ArgumentException("Password field was missing from encrypted attribute");
        }
        DateTime passwordUpdateTimestampUTC = DateTime.FromFileTimeUtc(
            long.Parse(
                encryptedRaw.UpdateTimestamp,
                NumberStyles.HexNumber
            )
        );
        return new(
            encryptedRaw.AccountName!,
            encryptedRaw.Password!,
            passwordUpdateTimestampUTC
        );
    }
    private EncryptedInner(string accountName, string password, DateTime passwordUpdateTimestampUTC) {
        AccountName = accountName;
        Password = password;
        PasswordUpdateTimestampUTC = passwordUpdateTimestampUTC;
    }
}