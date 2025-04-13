using System;

#pragma warning disable CS8618
namespace SapphTools.Laps;
/// <summary>
/// Represents metadata about a LAPS-managed account password, including its source, decryption status, and associated machine/account information.
/// </summary>
public abstract class PasswordInfo {
    /// <summary>
    /// The NetBIOS or DNS name of the computer associated with the password.
    /// </summary>
    public string ComputerName { get; protected set; }

    /// <summary>
    /// The full Active Directory distinguished name (DN) of the computer object.
    /// </summary>
    public string DistinguishedName { get; protected set; }

    /// <summary>
    /// The username context under which the LAPS password request was executed.
    /// </summary>
    public string Account { get; protected set; }

    /// <summary>
    /// The timestamp of the last password update, if known.
    /// </summary>
    public DateTime? PasswordUpdateTime { get; protected set; }

    /// <summary>
    /// The expiration timestamp for the current password, if defined by policy.
    /// </summary>
    public DateTime? ExpirationTimestamp { get; protected set; }

    /// <summary>
    /// The source or type of password that was retrieved (e.g., cleartext, encrypted, history).
    /// </summary>
    public PasswordSource Source { get; protected set; }

    /// <summary>
    /// The outcome of the password decryption process, if applicable.
    /// </summary>
    public DecryptionStatus DecryptionStatus { get; protected set; }

    /// <summary>
    /// The security group or SID that was authorized (or would have been authorized) to decrypt the password.
    /// </summary>
    public string AuthorizedDecryptor { get; protected set; }
}
#pragma warning restore CS8618