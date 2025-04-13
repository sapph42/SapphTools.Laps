using System;

#nullable enable
namespace SapphTools.Laps.Internal;
internal readonly struct AccountPasswordAttributes {
    public string Password { get; }
    public byte[] EncryptedPassword { get; }
    public byte[][] EncryptedPasswordHistory { get; }
    public byte[] EncryptedDSRMPassword { get; }
    public byte[][] EncryptedDSRMPasswordHistory { get; }
    public DateTime? PasswordExpiration { get; }
    public string LegacyPassword { get; }
    public DateTime? LegacyPasswordExpiration { get; }

    public AccountPasswordAttributes(
        string password,
        byte[] encryptedPassword,
        byte[][] encryptedPasswordHistory,
        byte[] encryptedDSRMPassword,
        byte[][] encryptedDSRMPasswordHistory,
        DateTime? passwordExpiration,
        string legacyPassword,
        DateTime? legacyPasswordExpiration) {
        Password = password;
        EncryptedPassword = encryptedPassword;
        EncryptedPasswordHistory = encryptedPasswordHistory;
        EncryptedDSRMPassword = encryptedDSRMPassword;
        EncryptedDSRMPasswordHistory = encryptedDSRMPasswordHistory;
        PasswordExpiration = passwordExpiration;
        LegacyPassword = legacyPassword;
        LegacyPasswordExpiration = legacyPasswordExpiration;
    }
}