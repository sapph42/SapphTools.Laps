using System.Collections.Generic;
using SapphTools.Laps.Internal;

#nullable enable
namespace SapphTools.Laps;
/// <summary>
/// Provides a public interface for querying LAPS-managed local administrator passwords from Active Directory,
/// including support for historical credentials, snapshots, and cleartext or secure string output formats.
/// </summary>
public class Laps {
    private readonly LapsInternal laps = new();

    /// <summary>
    /// Specifies the name of the Active Directory domain to connect to.
    /// If not set, the current domain of the executing machine will be used.
    /// </summary>
    public string Domain {
        get => laps.Domain;
        set => laps.Domain = value;
    }

    /// <summary>
    /// Specifies the domain controller to query, or the remote server hosting an AD Snapshot Browser instance.
    /// </summary>
    public string? DomainController {
        get => laps.DomainController;
        set => laps.DomainController = value;
    }

    /// <summary>
    /// Indicates whether to return older (historical) LAPS credentials associated with the computer object, if available.
    /// </summary>
    public bool IncludeHistory {
        get => laps.IncludeHistory;
        set => laps.IncludeHistory = value;
    }

    /// <summary>
    /// If set to <c>true</c>, passwords will be returned in cleartext.
    /// If <c>false</c> (default), passwords will be returned as <see cref="System.Security.SecureString"/> objects.
    /// </summary>
    public bool AsPlainText {
        get => laps.AsPlainText;
        set => laps.AsPlainText = value;
    }

    /// <summary>
    /// Specifies the port used when connecting to an Active Directory Snapshot Browser server.
    /// </summary>
    public int? Port {
        get => laps.Port;
        set => laps.Port = value;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Laps"/> class.
    /// The <see cref="Domain"/> property will default to the currently joined domain.
    /// </summary>
    public Laps() { }

    /// <summary>
    /// Queries Windows LAPS (Local Administrator Password Solution) credentials from Active Directory for a specified computer identity.
    /// </summary>
    /// <remarks>
    /// The following input formats are supported for <paramref name="identity"/>:
    /// <list type="bullet">
    ///   <item><description><c>distinguishedName</c> (begins with <c>CN=</c>)</description></item>
    ///   <item><description><c>samAccountName</c> (typically ends with a <c>$</c>)</description></item>
    ///   <item><description><c>dnsHostName</c> (contains at least one period <c>.</c>)</description></item>
    ///   <item><description><c>name</c> (used when no other format matches)</description></item>
    /// </list>
    /// </remarks>
    /// <param name="identity">The name or identifier of the computer to retrieve LAPS credentials for.</param>
    /// <returns>
    /// A collection of <see cref="PasswordInfo"/> objects representing the retrieved LAPS credentials.
    /// </returns>
    public IEnumerable<PasswordInfo> GetPasswordInfo(string identity) => laps.ProcessIdentity(identity);
}
