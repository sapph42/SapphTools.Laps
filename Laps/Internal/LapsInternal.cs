using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Security.Principal;
using static SapphTools.Laps.Internal.LapsNative;
using static SapphTools.Laps.Internal.LapsStatic;

#nullable enable
namespace SapphTools.Laps.Internal;
internal class LapsInternal : IDisposable {
    private LocalMachineInfo? _localMachineInfo;
    private readonly LdapConnectionInfo _ldapConnectionInfo;
    private readonly LdapConnection _ldapConn;
    private WindowsIdentity _identity = WindowsIdentity.GetCurrent();
    private bool _disposed;

    public string Domain;

    public string? DomainController;

    public bool IncludeHistory { get; set; } = false;

    public bool AsPlainText { get; set; } = false;

    public int? Port { get; set; }

    public LapsInternal() : this(System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain().Name) { }
    public LapsInternal(string domain) {
        InitializeLocalMachineInfo();
        Domain = domain;
        _ldapConn = BindToDomainController(Domain, DomainController, Port);
        _ldapConnectionInfo = GetLdapConnectionInfo(_ldapConn);
    }
    private void AddEncryptedPasswordSet(
        List<PasswordInfo> outputData,
        ComputerNameInfo computer,
        byte[] currentPassword,
        byte[][]? historyPasswords,
        PasswordSource currentSource,
        PasswordSource historySource,
        DateTime? expirationUtc) {
        PasswordInfo item = BuildPasswordInfoFromEncryptedPassword(
            computer,
            currentSource,
            currentPassword,
            expirationUtc
        );
        outputData.Add(item);

        if (!IncludeHistory || historyPasswords is not { Length: > 0 }) {
            return;
        }

        SortedList<DateTime, PasswordInfo> sorted = new(new DescendingDateTimeComparer());

        foreach (byte[] blob in historyPasswords) {
            if (blob is null or { Length: 0 }) {
                continue;
            }

            item = BuildPasswordInfoFromEncryptedPassword(computer, historySource, blob, null);

            DateTime key = item switch {
                PasswordInfoClearText clear => clear.PasswordUpdateTime ?? DateTime.MinValue,
                PasswordInfoSecureString secure => secure.PasswordUpdateTime ?? DateTime.MinValue,
                _ => throw new ArgumentException("Unexpected password info type")
            };

            sorted.Add(key, item);
        }

        foreach (PasswordInfo entry in sorted.Values) {
            outputData.Add(entry);
        }
    }
    public IEnumerable<PasswordInfo> ProcessIdentity(string Identity) {
        List<PasswordInfo> outputData = new();
        ComputerNameInfo computerNameInfo = GetComputerNameInfo(_ldapConn, _ldapConnectionInfo, Identity);

        AccountPasswordAttributes passwordAttributes =
            GetPasswordAttributes(_ldapConn, computerNameInfo.DistinguishedName) ??
            throw new LapsException($"Failed to query password attributes for the '{Identity}' object in AD");
        int totalPasswordObjects = passwordAttributes.EncryptedDSRMPassword.Length + 
            passwordAttributes.EncryptedDSRMPasswordHistory.Length + 
            passwordAttributes.EncryptedPassword.Length + 
            passwordAttributes.EncryptedPasswordHistory.Length;
        if (totalPasswordObjects == 0) {
            PasswordInfo dummy;
            if (AsPlainText) {
                dummy = new PasswordInfoClearText(
                    computerNameInfo.Name,
                    computerNameInfo.DistinguishedName,
                    _identity.Name,
                    string.Empty,
                    null,
                    null,
                    PasswordSource.PasswordMissing,
                    DecryptionStatus.Unauthorized,
                    string.Empty);
            } else {
                dummy = new PasswordInfoSecureString(
                    computerNameInfo.Name,
                    computerNameInfo.DistinguishedName,
                    _identity.Name,
                    new System.Security.SecureString(),
                    null,
                    null,
                    PasswordSource.PasswordMissing,
                    DecryptionStatus.Unauthorized,
                    string.Empty);
            }
            outputData.Add(dummy);
            return outputData;
        }
        DateTime? passwordExpUtc = passwordAttributes.PasswordExpiration?.ToUniversalTime();

        if (passwordAttributes.EncryptedPassword != null) {
            AddEncryptedPasswordSet(
                outputData,
                computerNameInfo,
                passwordAttributes.EncryptedPassword,
                passwordAttributes.EncryptedPasswordHistory,
                PasswordSource.EncryptedPassword,
                PasswordSource.EncryptedPasswordHistory,
                passwordExpUtc
            );
        } else if (passwordAttributes.EncryptedDSRMPassword != null) {
            AddEncryptedPasswordSet(
                outputData,
                computerNameInfo,
                passwordAttributes.EncryptedDSRMPassword,
                passwordAttributes.EncryptedDSRMPasswordHistory,
                PasswordSource.EncryptedDSRMPassword,
                PasswordSource.EncryptedDSRMPasswordHistory,
                passwordExpUtc
            );
        } else if (!string.IsNullOrEmpty(passwordAttributes.Password)) {
            EncryptedPasswordAttributeInner inner = EncryptedPasswordAttributeInner.ParseFromJson(passwordAttributes.Password);
            outputData.Add(BuildPasswordInfo(
                computerNameInfo,
                inner.AccountName,
                inner.Password,
                inner.PasswordUpdateTimestampUTC,
                passwordExpUtc,
                PasswordSource.CleartextPassword,
                DecryptionStatus.NotApplicable,
                "NotApplicable"
            ));
        } else if (!string.IsNullOrEmpty(passwordAttributes.LegacyPassword)) {
            outputData.Add(BuildPasswordInfo(
                computerNameInfo,
                null,
                passwordAttributes.LegacyPassword,
                null,
                passwordExpUtc,
                PasswordSource.LegacyLapsCleartextPassword,
                DecryptionStatus.NotApplicable,
                "NotApplicable"
            ));
        }

        return outputData;
    }
    private void InitializeLocalMachineInfo() {
        if (_localMachineInfo is null) {
            string dnsHostName = QueryLocalComputerName(COMPUTER_NAME_FORMAT.ComputerNameDnsFullyQualified);
            string netbiosName = QueryLocalComputerName(COMPUTER_NAME_FORMAT.ComputerNameNetBIOS);
            LsaDnsDomainInfo lsaDnsDomainInfo = LsaPolicy.QueryDnsDomainInfo();
            LsaDomainInfo lsaPrimaryDomainInfo = LsaPolicy.QueryPrimaryDomainInfo();
            LsaDomainInfo lsaAccountDomainInfo = LsaPolicy.QueryAccountDomainInfo();
            bool flag = !string.IsNullOrEmpty(lsaPrimaryDomainInfo.Sid) && !string.IsNullOrEmpty(lsaAccountDomainInfo.Sid) && StringComparer.OrdinalIgnoreCase.Equals(lsaPrimaryDomainInfo.Sid, lsaAccountDomainInfo.Sid);
            bool runningOnRODC = false;
            _localMachineInfo = new LocalMachineInfo(dnsHostName, netbiosName, flag, runningOnRODC, lsaDnsDomainInfo, lsaPrimaryDomainInfo, lsaAccountDomainInfo);
        }
    }
    private PasswordInfo BuildPasswordInfoFromEncryptedPassword(ComputerNameInfo computerNameInfo, PasswordSource passwordSource, byte[] encryptedPassword, DateTime? passwordExpirationTimestampUTC) {
        EncryptedPasswordAttributeState encryptedPasswordAttributeState = ParseAndDecryptDirectoryPassword(_identity, encryptedPassword, out DecryptionStatus decryptionStatus);
        string? account;
        string? password;
        DateTime? passwordUpdateTimeUTC;
        if (decryptionStatus == DecryptionStatus.Success) {
            account = encryptedPasswordAttributeState.InnerState?.AccountName;
            password = encryptedPasswordAttributeState.InnerState?.Password;
            passwordUpdateTimeUTC = encryptedPasswordAttributeState.InnerState?.PasswordUpdateTimestampUTC;
        } else {
            account = null;
            password = null;
            passwordUpdateTimeUTC = encryptedPasswordAttributeState.PrefixInfo.UpdateTimeStampUTC;
        }
        return BuildPasswordInfo(computerNameInfo, account, password, passwordUpdateTimeUTC, passwordExpirationTimestampUTC, passwordSource, decryptionStatus, encryptedPasswordAttributeState.AuthorizedDecryptorSid);
    }
    private PasswordInfo BuildPasswordInfo(ComputerNameInfo computerNameInfo, string? account, string? password, DateTime? passwordUpdateTimeUTC, DateTime? expirationTimestampUTC, PasswordSource source, DecryptionStatus decryptionStatus, string authorizedDecryptor) {
        return AsPlainText
            ? new PasswordInfoClearText(
                computerNameInfo.Name,
                computerNameInfo.DistinguishedName,
                account ?? string.Empty,
                password ?? string.Empty,
                passwordUpdateTimeUTC?.ToLocalTime(),
                expirationTimestampUTC?.ToLocalTime(),
                source,
                decryptionStatus,
                authorizedDecryptor
             )
            : new PasswordInfoSecureString(
            computerNameInfo.Name,
            computerNameInfo.DistinguishedName,
            account ?? string.Empty,
            string.IsNullOrEmpty(password) ? new() : ConvertStringToSecureString(password!),
            passwordUpdateTimeUTC?.ToLocalTime(),
            expirationTimestampUTC?.ToLocalTime(),
            source,
            decryptionStatus,
            authorizedDecryptor
        );
    }
    public void Dispose() {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
    private void Dispose(bool disposing) {
        if (!_disposed) {
            if (disposing && _ldapConn != null) {
                _ldapConn.Dispose();
            }
            _disposed = true;
        }
    }
    ~LapsInternal() {
        Dispose(disposing: false);
    }
}
