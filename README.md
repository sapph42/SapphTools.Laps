# SapphTools.Laps

A drop-in library capable of retrieving LAPS data from a domain controller. PowerShell module not required, as this is a refactor of Microsoft's code IN the PowerShell module - cleaned up, modernized up to C# 10, and made sane.

## LapsConnection

Provides a public interface for querying LAPS-managed local administrator passwords from Active Directory,
including support for historical credentials, snapshots, and output format options.

### Properties

- **Domain** — Specifies the name of the Active Directory domain to connect to. If not set, the current domain of the executing machine will be used.
- **DomainController** — Specifies the domain controller to query, or the remote server hosting an AD Snapshot Browser instance.
- **IncludeHistory** — Indicates whether to return older (historical) LAPS credentials associated with the computer object, if available.
- **AsPlainText** — If set to true, passwords are returned in cleartext; otherwise, they are returned as SecureString.
- **Port** — Specifies the port used when connecting to an Active Directory Snapshot Browser server.

### Methods

#### GetPasswordInfo(string identity)

Queries Windows LAPS (Local Administrator Password Solution) credentials from Active Directory for a specified computer identity.

##### Parameters

- **identity** — The name or identifier of the computer to retrieve LAPS credentials for.

##### Returns

A collection of `PasswordInfo` objects representing the retrieved LAPS credentials.

##### Remarks

The following input formats are supported for `identity`:

- `distinguishedName` (begins with `CN=`)
- `samAccountName` (typically ends with `$`)
- `dnsHostName` (contains at least one period `.`)
- `name` (used when no other format matches)

## DecryptionStatus

Represents the result of attempting to decrypt a LAPS-managed password.

### Enum Members

- **NotApplicable** — Decryption was not attempted or is not applicable (e.g., clear-text password).
- **Success** — The password was successfully decrypted.
- **Unauthorized** — The current user is not authorized to decrypt the password.
- **Error** — An unexpected error occurred during decryption.

## PasswordSource

Identifies the source or type of the LAPS password that was retrieved.

### Enum Members

- **PasswordMissing** — No password was found in the LAPS attributes for the account.
- **LegacyLapsCleartextPassword** — The password was retrieved from the legacy ms-Mcs-AdmPwd attribute (cleartext).
- **CleartextPassword** — The password was retrieved from the new cleartext LAPS v2 attribute (msLAPS-Password).
- **EncryptedPassword** — The password was retrieved from the encrypted LAPS v2 attribute (msLAPS-EncryptedPassword).
- **EncryptedPasswordHistory** — The password was retrieved from the encrypted password history attribute (msLAPS-EncryptedPasswordHistory).
- **EncryptedDSRMPassword** — The password was retrieved from the encrypted DSRM password attribute (msLAPS-EncryptedDSRMPassword).
- **EncryptedDSRMPasswordHistory** — The password was retrieved from the encrypted DSRM password history attribute (msLAPS-EncryptedDSRMPasswordHistory).

## PasswordInfo

Abstract base class representing metadata about a LAPS-managed account password, including its source,
decryption status, and associated machine/account information.

### Properties

- **ComputerName** — The NetBIOS or DNS name of the computer associated with the password.
- **DistinguishedName** — The full Active Directory distinguished name (DN) of the computer object.
- **Account** — The username context under which the LAPS password request was executed.
- **PasswordUpdateTime** — The timestamp of the last password update, if known.
- **ExpirationTimestamp** — The expiration timestamp for the current password, if defined by policy.
- **Source** — The source or type of password that was retrieved (e.g., cleartext, encrypted, history).
- **DecryptionStatus** — The outcome of the password decryption process, if applicable.
- **AuthorizedDecryptor** — The security group or SID that was authorized (or would have been authorized) to decrypt the password.

## PasswordInfoClearText

Represents a LAPS password retrieved in cleartext form. Inherits from PasswordInfo.

### Properties

- **Password** — The cleartext password for the managed local account.

## PasswordInfoSecureString

Represents a LAPS password that was retrieved in encrypted form and successfully decrypted into a SecureString. Inherits from PasswordInfo.

### Properties

- **Password** — The decrypted LAPS password as a SecureString.
