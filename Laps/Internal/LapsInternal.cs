using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using static SapphTools.Laps.Internal.LapsNative;
using static SapphTools.Laps.Internal.LapsStatic;
using static SapphTools.Laps.Internal.OSNative;

#nullable enable
namespace SapphTools.Laps.Internal;
internal class LapsInternal : IDisposable {
    private LocalMachineInfo? _localMachineInfo;
    private readonly LdapConnectionInfo _ldapConnectionInfo;
    private LdapConnection _ldapConn;
    private IntPtr _hDecryptionToken;
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


    public List<PasswordInfo> ProcessIdentity(string Identity) {
        List<PasswordInfo> outputData = new();
        ComputerNameInfo computerNameInfo = GetComputerNameInfo(_ldapConn, _ldapConnectionInfo, Identity);
        AccountPasswordAttributes passwordAttributes =
            GetPasswordAttributes(_ldapConn, computerNameInfo.DistinguishedName) ??
            throw new LapsException($"Failed to query password attributes for the '{Identity}' object in AD");
        DateTime? passwordExpUtc;
        if (passwordAttributes.EncryptedPassword != null) {
            passwordExpUtc = passwordAttributes.PasswordExpiration?.ToUniversalTime();
            PasswordInfo item = BuildPasswordInfoFromEncryptedPassword(
                computerNameInfo,
                PasswordSource.EncryptedPassword,
                passwordAttributes.EncryptedPassword,
                passwordExpUtc
            );
            outputData.Add(item);
            if (IncludeHistory && passwordAttributes.EncryptedPasswordHistory != null && passwordAttributes.EncryptedPasswordHistory.Length != 0) {
                SortedList<DateTime, PasswordInfo> sortedList = new(new DescendingDateTimeComparer());
                byte[][] encryptedPasswordHistory = passwordAttributes.EncryptedPasswordHistory;
                foreach (byte[] array in encryptedPasswordHistory) {
                    if (array == null || array.Length == 0) {
                        continue;
                    }
                    item = BuildPasswordInfoFromEncryptedPassword(
                        computerNameInfo,
                        PasswordSource.EncryptedPasswordHistory,
                        array,
                        null
                    );
                    DateTime key;
                    if (item is PasswordInfoClearText passwordInfoClearText) {
                        key = passwordInfoClearText.PasswordUpdateTime ?? DateTime.MinValue;
                    } else {
                        if (item is not PasswordInfoSecureString) {
                            throw new ArgumentException("Unexpected password info type");
                        }
                        PasswordInfoSecureString passwordInfoSecureString = (PasswordInfoSecureString)item;
                        key = passwordInfoSecureString.PasswordUpdateTime ?? DateTime.MinValue;
                    }
                    sortedList.Add(key, item);
                }
                foreach (KeyValuePair<DateTime, PasswordInfo> passwordHistory in sortedList) {
                    outputData.Add(passwordHistory.Value);
                }
            }
        } else if (passwordAttributes.EncryptedDSRMPassword != null) {
            if (passwordAttributes.EncryptedDSRMPasswordHistory != null && passwordAttributes.EncryptedDSRMPasswordHistory.Length != 0) {
            }
            passwordExpUtc = passwordAttributes.PasswordExpiration?.ToUniversalTime();
            PasswordInfo item = BuildPasswordInfoFromEncryptedPassword(
                computerNameInfo,
                PasswordSource.EncryptedDSRMPassword,
                passwordAttributes.EncryptedDSRMPassword,
                passwordExpUtc
            );
            outputData.Add(item);
            if (IncludeHistory && passwordAttributes.EncryptedDSRMPasswordHistory != null && passwordAttributes.EncryptedDSRMPasswordHistory.Length != 0) {
                SortedList<DateTime, PasswordInfo> clearTextHistory = new(new DescendingDateTimeComparer());
                byte[][] encryptedPasswordHistory = passwordAttributes.EncryptedDSRMPasswordHistory;
                foreach (byte[] encryptedPassword in encryptedPasswordHistory) {
                    if (encryptedPassword == null || encryptedPassword.Length == 0) {
                        continue;
                    }
                    item = BuildPasswordInfoFromEncryptedPassword(
                        computerNameInfo,
                        PasswordSource.EncryptedDSRMPasswordHistory,
                        encryptedPassword,
                        null
                    );
                    DateTime key;
                    if (item is PasswordInfoClearText passwordInfoClearText) {
                        key = passwordInfoClearText.PasswordUpdateTime ?? DateTime.MinValue;
                    } else {
                        if (item is not PasswordInfoSecureString) {
                            throw new ArgumentException("Unexpected password info type");
                        }
                        PasswordInfoSecureString passwordInfoSecureString = (PasswordInfoSecureString)item;
                        key = passwordInfoSecureString.PasswordUpdateTime ?? DateTime.MinValue;
                    }
                    clearTextHistory.Add(key, item);
                }
                foreach (KeyValuePair<DateTime, PasswordInfo> item3 in clearTextHistory) {
                    outputData.Add(item3.Value);
                }
            }
        } else if (!string.IsNullOrEmpty(passwordAttributes.Password)) {
            EncryptedPasswordAttributeInner encryptedPasswordAttributeInner = EncryptedPasswordAttributeInner.ParseFromJson(passwordAttributes.Password);
            passwordExpUtc = passwordAttributes.PasswordExpiration?.ToUniversalTime();
            PasswordInfo item = BuildPasswordInfo(computerNameInfo, encryptedPasswordAttributeInner.AccountName, encryptedPasswordAttributeInner.Password, encryptedPasswordAttributeInner.PasswordUpdateTimestampUTC, passwordExpUtc, PasswordSource.CleartextPassword, DecryptionStatus.NotApplicable, "NotApplicable");
            outputData.Add(item);
        } else if (!string.IsNullOrEmpty(passwordAttributes.LegacyPassword)) {
            passwordExpUtc = passwordAttributes.PasswordExpiration?.ToUniversalTime();
            PasswordInfo item = BuildPasswordInfo(computerNameInfo, null, passwordAttributes.LegacyPassword, null, passwordExpUtc, PasswordSource.LegacyLapsCleartextPassword, DecryptionStatus.NotApplicable, "NotApplicable");
            outputData.Add(item);
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
        EncryptedPasswordAttributeState encryptedPasswordAttributeState = ParseAndDecryptDirectoryPassword(_hDecryptionToken, encryptedPassword, out DecryptionStatus decryptionStatus);
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
        if (AsPlainText) {
            return new PasswordInfoClearText(
                computerNameInfo.Name,
                computerNameInfo.DistinguishedName,
                account ?? string.Empty,
                password ?? string.Empty,
                passwordUpdateTimeUTC?.ToLocalTime(),
                expirationTimestampUTC?.ToLocalTime(),
                source,
                decryptionStatus,
                authorizedDecryptor
             );
        }
        return new PasswordInfoSecureString(
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
            if (_hDecryptionToken != IntPtr.Zero) {
                CloseHandle(_hDecryptionToken);
                _hDecryptionToken = IntPtr.Zero;
            }
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
