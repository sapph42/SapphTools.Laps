using System;

#nullable enable
namespace SapphTools.Laps;
/// <summary>
/// Represents a LAPS password retrieved in cleartext form.
/// </summary>
public class PasswordInfoClearText : PasswordInfo {
    /// <summary>
    /// The cleartext password for the managed local account.
    /// </summary>
    public string Password { get; private set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordInfoClearText"/> class.
    /// Intended for internal use only.
    /// </summary>
    internal PasswordInfoClearText(
        string computerName,
        string distinguishedName,
        string account,
        string password,
        DateTime? passwordUpdateTime,
        DateTime? expirationTimestamp,
        PasswordSource source,
        DecryptionStatus decryptionStatus,
        string authorizedDecryptor) {
        ComputerName = computerName;
        DistinguishedName = distinguishedName;
        Account = account;
        Password = password;
        PasswordUpdateTime = passwordUpdateTime;
        ExpirationTimestamp = expirationTimestamp;
        Source = source;
        DecryptionStatus = decryptionStatus;
        AuthorizedDecryptor = authorizedDecryptor;
    }
}