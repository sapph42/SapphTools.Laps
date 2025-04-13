using System;
using System.Security;

#nullable enable
namespace SapphTools.Laps;
/// <summary>
/// Represents a LAPS password that was retrieved in encrypted form and successfully decrypted into a <see cref="SecureString"/>.
/// </summary>
public class PasswordInfoSecureString : PasswordInfo {
    /// <summary>
    /// The decrypted LAPS password as a <see cref="SecureString"/>.
    /// </summary>
    public SecureString Password { get; private set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordInfoSecureString"/> class.
    /// Intended for internal use only.
    /// </summary>
    internal PasswordInfoSecureString(
        string computerName,
        string distinguishedName,
        string account,
        SecureString password,
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