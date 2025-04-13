using System;
using System.Globalization;

#nullable enable
namespace SapphTools.Laps.Internal;
internal readonly struct EncryptedPasswordAttributeInner {
    public string AccountName { get; }
    public string Password { get; }
    public DateTime PasswordUpdateTimestampUTC { get; }

    public static EncryptedPasswordAttributeInner ParseFromJson(string passwordJson) {
        EncryptedPasswordAttributeRaw? encryptedPasswordAttributeRaw =
            EncryptedPasswordAttributeRaw.Parse(passwordJson) ??
            throw new ArgumentException("Failed to parse JSON.");
        if (string.IsNullOrEmpty(encryptedPasswordAttributeRaw.AccountName)) {
            throw new ArgumentException("AccountName field was missing from encrypted attribute");
        }
        if (string.IsNullOrEmpty(encryptedPasswordAttributeRaw.UpdateTimestamp)) {
            throw new ArgumentException("UpdateTimestamp field was missing from encrypted attribute");
        }
        if (string.IsNullOrEmpty(encryptedPasswordAttributeRaw.Password)) {
            throw new ArgumentException("Password field was missing from encrypted attribute");
        }
        DateTime passwordUpdateTimestampUTC = DateTime.FromFileTimeUtc(
            long.Parse(
                encryptedPasswordAttributeRaw.UpdateTimestamp,
                NumberStyles.HexNumber
            )
        );
        return new(
            encryptedPasswordAttributeRaw.AccountName!,
            encryptedPasswordAttributeRaw.Password!,
            passwordUpdateTimestampUTC
        );
    }
    private EncryptedPasswordAttributeInner(string accountName, string password, DateTime passwordUpdateTimestampUTC) {
        AccountName = accountName;
        Password = password;
        PasswordUpdateTimestampUTC = passwordUpdateTimestampUTC;
    }
}