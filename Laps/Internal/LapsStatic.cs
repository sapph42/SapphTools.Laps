using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static SapphTools.Laps.Internal.LapsNative;
using static SapphTools.Laps.Internal.OSNative;

#nullable enable
namespace SapphTools.Laps.Internal;
internal static partial class LapsStatic {
    public static void AllocateManagedBuffer(IntPtr pbBuffer, uint cbBuffer, out byte[] bytes) {
        byte[] array = new byte[cbBuffer];
        Marshal.Copy(pbBuffer, array, 0, Convert.ToInt32(cbBuffer));
        bytes = array;
    }
    public static void AllocateNativeBuffer(byte[] bytes, out IntPtr pbBuffer, out uint cbBuffer) {
        IntPtr intPtr;
        uint num;
        if (bytes != null && bytes.Length != 0) {
            intPtr = Marshal.AllocHGlobal(bytes.Length);
            num = (uint)bytes.Length;
            Marshal.Copy(bytes, 0, intPtr, bytes.Length);
        } else {
            intPtr = IntPtr.Zero;
            num = 0u;
        }
        pbBuffer = intPtr;
        cbBuffer = num;
    }
    public static LdapConnection BindToDomainController(string Domain, string? DomainController, int? port) {
        NetworkCredential credential2;
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new(identity);
        if (principal.IsInRole(WindowsBuiltInRole.Administrator)) {
            credential2 = CredentialCache.DefaultNetworkCredentials;
        } else {
            throw new LapsException("Must run elevated!");
        }
        LdapConnection result;
        if (!string.IsNullOrEmpty(DomainController) && port.HasValue) {
            result = GetLdapServerConnection(DomainController!, port, credential2);
        } else if (!string.IsNullOrEmpty(Domain)) {
            result = GetLdapConnection(Domain, writable: true, credential2);
        } else {
            result = GetLdapConnection(null, writable: true, credential2);
        }
        return result;
    }
    public static SecureString ConvertStringToSecureString(string someString) {
        SecureString secureString = new();
        foreach (char c in someString) {
            secureString.AppendChar(c);
        }
        secureString.MakeReadOnly();
        return secureString;
    }
    public static uint DecryptBytesHelper(IntPtr hDecryptionToken, byte[] encryptedData, out byte[] decryptedBytes) {
        IntPtr pbBuffer = IntPtr.Zero;
        IntPtr pbDecryptedData = IntPtr.Zero;
        decryptedBytes = Array.Empty<byte>();
        uint num;
        try {
            AllocateNativeBuffer(encryptedData, out pbBuffer, out var cbBuffer);
            num = DecryptNormalMode(hDecryptionToken, pbBuffer, cbBuffer, 0u, out pbDecryptedData, out var cbDecryptedData);
            if (num != 0) {
                return num;
            }
            AllocateManagedBuffer(pbDecryptedData, cbDecryptedData, out var bytes);
            decryptedBytes = bytes;
        } catch (Exception) {
            num = 2147483650u;
            decryptedBytes = Array.Empty<byte>();
        } finally {
            if (pbDecryptedData != IntPtr.Zero) {
                LocalFree(pbDecryptedData);
            }
            if (pbBuffer != IntPtr.Zero) {
                LocalFree(pbBuffer);
            }
        }
        return num;
    }
    public static string EscapeDNForFilter(string dn) {
        Regex escapedBackslash = new("\\\\5c");
        Regex escapedHexPair = new("(^|[^\\\\])\\\\([0-9a-fA-F][0-9a-fA-F])");
        if (string.IsNullOrEmpty(dn)) {
            return dn;
        }
        dn = escapedBackslash.Replace(dn, "\\\\5c");
        return escapedHexPair.Replace(dn, "$1\\\\$2");
    }
    public static string ExtractAndResolveSidProtectionString(byte[] encryptedData) {
        IntPtr pbBuffer = IntPtr.Zero;
        string pszSidProtectionString = "<unavailable>";
        try {
            AllocateNativeBuffer(encryptedData, out pbBuffer, out var cbBuffer);
            uint sidProtectionString = GetSidProtectionString(
                pbBuffer,
                cbBuffer,
                out uint pSecondaryStatus,
                out pszSidProtectionString
            );
            if (sidProtectionString != 0) {
                pszSidProtectionString = "<unavailable>";
                return pszSidProtectionString;
            }
        } catch {
            pszSidProtectionString = "<unavailable>";
            return pszSidProtectionString;
        } finally {
            if (pbBuffer != IntPtr.Zero) {
                LocalFree(pbBuffer);
            }
        }
        return ResolveSidProtectionString(pszSidProtectionString);
    }
    public static ComputerNameInfo GetComputerNameInfo(LdapConnection ldapConn, LdapConnectionInfo ldapConnectionInfo, string Identity) {
        string? name = null;
        string? distinguishedName = null;
        string? samAccountName = null;
        string? dnsHostName = null;
        string[] value = { "name", "distinguishedName", "samAccountName", "dnsHostName" };
        string text2;
        if (Identity.StartsWith("CN=", StringComparison.InvariantCultureIgnoreCase)) {
            string text = EscapeDNForFilter(Identity);
            text2 = string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "distinguishedName", text);
        } else if (Identity[^1] == '$') {
            text2 = string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "samAccountName", Identity);
        } else if (Identity.Contains('.')) {
            text2 = string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "dnsHostName", Identity);
        } else {
            text2 = string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "name", Identity);
        }
        SearchRequest searchRequest = new() {
            DistinguishedName = ldapConnectionInfo.Domain.DomainNC,
            Filter = text2,
            Scope = SearchScope.Subtree
        };
        searchRequest.Attributes.AddRange(value);
        SearchResponse? searchResponse = ldapConn.SendRequest(searchRequest) as SearchResponse;
        if (searchResponse is not null && searchResponse.Entries.Count != 1) {
            string text3;
            if (searchResponse.Entries.Count == 0) {
                text3 = $"Failed to find the '{Identity}' computer in AD";
            } else {
                StringBuilder stringBuilder = new();
                text3 = $"Found multiple ({searchResponse.Entries.Count}) results  for the target '{Identity}' identity in AD:";
                stringBuilder.AppendLine(text3);
                for (int i = 0; i < searchResponse.Entries.Count; i++) {
                    SearchResultEntry searchResultEntry = searchResponse.Entries[i];
                    stringBuilder.AppendLine(searchResultEntry.DistinguishedName);
                }
            }
            throw new LapsException(text3);
        }
        SearchResultEntry? searchResultEntry2 = searchResponse?.Entries[0];
        if (searchResultEntry2 is not null && searchResultEntry2.Attributes.Contains("name")) {
            name = searchResultEntry2.Attributes["name"].GetValues(typeof(string))[0] as string;
        }
        if (searchResultEntry2 is not null && searchResultEntry2.Attributes.Contains("distinguishedName")) {
            distinguishedName = searchResultEntry2.Attributes["distinguishedName"].GetValues(typeof(string))[0] as string;
        }
        if (searchResultEntry2 is not null && searchResultEntry2.Attributes.Contains("samAccountName")) {
            samAccountName = searchResultEntry2.Attributes["samAccountName"].GetValues(typeof(string))[0] as string;
        }
        if (searchResultEntry2 is not null && searchResultEntry2.Attributes.Contains("dnsHostName")) {
            dnsHostName = searchResultEntry2.Attributes["dnsHostName"].GetValues(typeof(string))[0] as string;
        }
        return new ComputerNameInfo(name, distinguishedName, samAccountName, dnsHostName);
    }
    private static LdapConnection GetConnectionWorker(string domainController, int? port, NetworkCredential? credential) {
        LdapConnection? ldapConnection = null;
        string server = $"{domainController}:{port ?? 389}";
        try {
            ldapConnection = new LdapConnection(server);
            ldapConnection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            ldapConnection.SessionOptions.Sealing = true;
            ldapConnection.SessionOptions.Signing = true;
            if (credential != null) {
                ldapConnection.Bind(credential);
            } else {
                ldapConnection.Bind();
            }
        } catch (Exception) {
            ldapConnection?.Dispose();
            throw;
        }
        return ldapConnection;
    }
    private static LdapConnection GetLdapConnection(string? domainName, bool writable, NetworkCredential credential) {
        uint num = 1073741840u;
        if (writable) {
            num |= 0x1000;
        }
        DCLocator dCLocatorInfo = DCLocator.LocateDCNoThrow(null, domainName, null, num)
            ?? throw new LapsException($"Failed to locate a domain controller in the '{domainName}' domain");

        return GetConnectionWorker(dCLocatorInfo.DomainControllerName, null, credential);
    }
    public static LdapConnectionInfo GetLdapConnectionInfo(LdapConnection ldapConn) {
        string[] value = { "configurationNamingContext", "defaultNamingContext", "dnsHostName", "rootDomainNamingContext", "schemaNamingContext", "domainControllerFunctionality", "domainFunctionality", "forestFunctionality", "supportedCapabilities" };
        SearchRequest searchRequest = new();
        searchRequest.Attributes.AddRange(value);
        searchRequest.Scope = SearchScope.Base;
        SearchResponse obj = (SearchResponse)ldapConn.SendRequest(searchRequest);
        string text = (string)obj.Entries[0].Attributes["rootDomainNamingContext"].GetValues(typeof(string))[0];
        string arg = (string)obj.Entries[0].Attributes["defaultNamingContext"].GetValues(typeof(string))[0];
        string text2 = (string)obj.Entries[0].Attributes["configurationNamingContext"].GetValues(typeof(string))[0];
        string text3 = (string)obj.Entries[0].Attributes["schemaNamingContext"].GetValues(typeof(string))[0];
        string domainNC = (string)obj.Entries[0].Attributes["defaultNamingContext"].GetValues(typeof(string))[0];
        string dnsHostNameDC = (string)obj.Entries[0].Attributes["dnsHostName"].GetValues(typeof(string))[0];
        string text4 = (string)obj.Entries[0].Attributes["domainControllerFunctionality"].GetValues(typeof(string))[0];
        int dcFunctionalLevel = ((!string.IsNullOrEmpty(text4)) ? int.Parse(text4, NumberFormatInfo.InvariantInfo) : 0);
        text4 = (string)obj.Entries[0].Attributes["domainFunctionality"].GetValues(typeof(string))[0];
        int domainFunctionalLevel = ((!string.IsNullOrEmpty(text4)) ? int.Parse(text4, NumberFormatInfo.InvariantInfo) : 0);
        text4 = (string)obj.Entries[0].Attributes["forestFunctionality"].GetValues(typeof(string))[0];
        int forestFunctionalLevel = ((!string.IsNullOrEmpty(text4)) ? int.Parse(text4, NumberFormatInfo.InvariantInfo) : 0);
        bool isRODC = false;
        byte[][] array = (byte[][])obj.Entries[0].Attributes["supportedCapabilities"].GetValues(typeof(byte[]));
        foreach (byte[] array2 in array) {
            string @string = Encoding.UTF8.GetString(array2, 0, array2.Length);
            if (StringComparer.InvariantCultureIgnoreCase.Equals(@string, "1.2.840.113556.1.4.1920")) {
                isRODC = true;
                break;
            }
        }
        searchRequest = new SearchRequest {
            DistinguishedName = "CN=Partitions," + text2,
            Scope = SearchScope.OneLevel
        };
        searchRequest.Attributes.Add("dnsRoot");
        searchRequest.Filter = string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "crossRef", "nCName", arg);
        string domainDnsHostName = (string)((SearchResponse)ldapConn.SendRequest(searchRequest)).Entries[0].Attributes["dnsRoot"].GetValues(typeof(string))[0];
        searchRequest = new SearchRequest {
            DistinguishedName = "CN=Partitions," + text2,
            Scope = SearchScope.OneLevel
        };
        searchRequest.Attributes.Add("dnsRoot");
        searchRequest.Filter = string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "crossRef", "nCName", text);
        string rootDomainDnsHostName = (string)((SearchResponse)ldapConn.SendRequest(searchRequest)).Entries[0].Attributes["dnsRoot"].GetValues(typeof(string))[0];
        searchRequest = new SearchRequest {
            DistinguishedName = text3,
            Scope = SearchScope.Base
        };
        searchRequest.Attributes.Add("fSMORoleOwner");

        string distinguishedName = ((string)((SearchResponse)ldapConn.SendRequest(searchRequest)).Entries[0].Attributes["fSMORoleOwner"].GetValues(typeof(string))[0])["CN=NTDS Settings,".Length..];
        searchRequest = new SearchRequest {
            DistinguishedName = distinguishedName,
            Scope = SearchScope.Base
        };
        searchRequest.Attributes.Add("dnsHostName");
        string schemaNamingMaster = (string)((SearchResponse)ldapConn.SendRequest(searchRequest)).Entries[0].Attributes["dnsHostName"].GetValues(typeof(string))[0];
        ForestInfo forestInfo = new(rootDomainDnsHostName, text, text2, text3, schemaNamingMaster, forestFunctionalLevel);
        DomainInfo domainInfo = new(domainDnsHostName, domainNC, domainFunctionalLevel);
        return new LdapConnectionInfo(dnsHostNameDC, dcFunctionalLevel, isRODC, forestInfo, domainInfo);
    }
    private static LdapConnection GetLdapServerConnection(string serverName, int? port, NetworkCredential? credential = null) {
        return GetConnectionWorker(serverName, port, credential);
    }
    public static AccountPasswordAttributes? GetPasswordAttributes(LdapConnection ldapConn, string computerDN) {
        string[] attributeList = { "msLAPS-PasswordExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" };
        DateTime? passwordExpiration = null;
        string? password = null;
        byte[] encryptedPassword = Array.Empty<byte>();
        byte[][] encryptedPasswordHistory = Array.Empty<byte[]>();
        byte[] encryptedDSRMPassword = Array.Empty<byte>();
        byte[][] encryptedDSRMPasswordHistory = Array.Empty<byte[]>();
        string? legacyPassword = null;
        DateTime? legacyPasswordExpiration = null;
        string text = EscapeDNForFilter(computerDN);
        string text2 = string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "distinguishedName", text);
        SearchRequest request = new(text, text2, SearchScope.Base, attributeList);
        if (ldapConn.SendRequest(request) is not SearchResponse searchResponse || searchResponse.Entries.Count != 1) {
            return null;
        }
        SearchResultEntry searchResultEntry = searchResponse.Entries[0];
        foreach (string attributeName2 in searchResultEntry.Attributes.AttributeNames) {
            if (StringComparer.InvariantCultureIgnoreCase.Equals(attributeName2, "msLAPS-PasswordExpirationTime")) {
                string? text5 = searchResultEntry.Attributes["msLAPS-PasswordExpirationTime"].GetValues(typeof(string))[0] as string;
                if (!string.IsNullOrEmpty(text5)) {
                    long fileTime = long.Parse(text5, NumberFormatInfo.InvariantInfo);
                    passwordExpiration = DateTime.FromFileTime(fileTime);
                }
                continue;
            }
            if (StringComparer.InvariantCultureIgnoreCase.Equals(attributeName2, "msLAPS-Password")) {
                password = searchResultEntry.Attributes["msLAPS-Password"].GetValues(typeof(string))[0] as string;
                continue;
            }
            if (StringComparer.InvariantCultureIgnoreCase.Equals(attributeName2, "msLAPS-EncryptedPassword")) {
                encryptedPassword = searchResultEntry.Attributes["msLAPS-EncryptedPassword"].GetValues(typeof(byte[]))[0] as byte[] ?? Array.Empty<byte>();
                continue;
            }
            if (StringComparer.InvariantCultureIgnoreCase.Equals(attributeName2, "msLAPS-EncryptedPasswordHistory")) {
                int count = searchResultEntry.Attributes["msLAPS-EncryptedPasswordHistory"].Count;
                encryptedPasswordHistory = new byte[count][];
                for (int i = 0; i < count; i++) {
                    encryptedPasswordHistory[i] = searchResultEntry.Attributes["msLAPS-EncryptedPasswordHistory"].GetValues(typeof(byte[]))[i] as byte[] ?? Array.Empty<byte>();
                }
            }
            if (StringComparer.InvariantCultureIgnoreCase.Equals(attributeName2, "msLAPS-EncryptedDSRMPassword")) {
                encryptedDSRMPassword = searchResultEntry.Attributes["msLAPS-EncryptedDSRMPassword"].GetValues(typeof(byte[]))[0] as byte[] ?? Array.Empty<byte>();
                continue;
            }
            if (StringComparer.InvariantCultureIgnoreCase.Equals(attributeName2, "msLAPS-EncryptedDSRMPasswordHistory")) {
                int count2 = searchResultEntry.Attributes["msLAPS-EncryptedDSRMPasswordHistory"].Count;
                encryptedDSRMPasswordHistory = new byte[count2][];
                for (int i = 0; i < count2; i++) {
                    encryptedDSRMPasswordHistory[i] = searchResultEntry.Attributes["msLAPS-EncryptedDSRMPasswordHistory"].GetValues(typeof(byte[]))[i] as byte[] ?? Array.Empty<byte>();
                }
            }
            if (StringComparer.InvariantCultureIgnoreCase.Equals(attributeName2, "ms-Mcs-AdmPwdExpirationTime")) {
                string text5 = searchResultEntry.Attributes["ms-Mcs-AdmPwdExpirationTime"].GetValues(typeof(string))[0] as string ?? string.Empty;
                if (!string.IsNullOrEmpty(text5)) {
                    long fileTime2 = long.Parse(text5, NumberFormatInfo.InvariantInfo);
                    legacyPasswordExpiration = DateTime.FromFileTime(fileTime2);
                }
            } else if (StringComparer.InvariantCultureIgnoreCase.Equals(attributeName2, "ms-Mcs-AdmPwd")) {
                legacyPassword = searchResultEntry.Attributes["ms-Mcs-AdmPwd"].GetValues(typeof(string))[0] as string ?? string.Empty;
            }
        }
        return new AccountPasswordAttributes(
            password ?? string.Empty,
            encryptedPassword,
            encryptedPasswordHistory,
            encryptedDSRMPassword,
            encryptedDSRMPasswordHistory,
            passwordExpiration,
            legacyPassword ?? string.Empty,
            legacyPasswordExpiration
        );
    }
    public static EncryptedPasswordAttributeState ParseAndDecryptDirectoryPassword(IntPtr hDecryptionToken, byte[] encryptedPasswordBytes, out DecryptionStatus decryptionStatus) {
        byte[] trailingBytes = Array.Empty<byte>();
        EncryptedPasswordAttributePrefixInfo encryptedPasswordAttributePrefixInfo = EncryptedPasswordAttributePrefixInfo.ParseFromBuffer(encryptedPasswordBytes);
        byte[] encryptedData = new byte[encryptedPasswordAttributePrefixInfo.EncryptedBufferSize];
        Buffer.BlockCopy(encryptedPasswordBytes, 16, encryptedData, 0, (int)encryptedPasswordAttributePrefixInfo.EncryptedBufferSize);
        string authorizedDecryptorSid = ExtractAndResolveSidProtectionString(encryptedData);
        EncryptedPasswordAttributeInner? innerState;
        switch (DecryptBytesHelper(hDecryptionToken, encryptedData, out byte[] decryptedBytes)) {
            case 0u:
                innerState = EncryptedPasswordAttributeInner.ParseFromJson(Encoding.Unicode.GetString(decryptedBytes));
                decryptionStatus = DecryptionStatus.Success;
                break;
            case 2148073516u:
                innerState = null;
                decryptionStatus = DecryptionStatus.Unauthorized;
                break;
            default:
                innerState = null;
                decryptionStatus = DecryptionStatus.Error;
                break;
        }
        uint num = (uint)(encryptedPasswordBytes.Length - 16) - encryptedPasswordAttributePrefixInfo.EncryptedBufferSize;
        if (num != 0) {
            trailingBytes = new byte[num];
            Buffer.BlockCopy(encryptedPasswordBytes, (int)(16 + encryptedPasswordAttributePrefixInfo.EncryptedBufferSize), trailingBytes, 0, (int)num);
        }
        return new EncryptedPasswordAttributeState(authorizedDecryptorSid, encryptedPasswordAttributePrefixInfo, innerState, trailingBytes);
    }
    public static string QueryLocalComputerName(COMPUTER_NAME_FORMAT nameFormat) {
        StringBuilder stringBuilder = new(300);
        int lpnSize = 300;
        if (!GetComputerNameEx(nameFormat, stringBuilder, ref lpnSize)) {
            throw new InvalidOperationException("Unable to query the local computer name");
        }
        return stringBuilder.ToString();

        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetComputerNameExW", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetComputerNameEx([In] COMPUTER_NAME_FORMAT NameType, [Out][MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpBuffer, [In][Out][MarshalAs(UnmanagedType.U4)] ref int lpnSize);

    }
    public static string ResolveSidProtectionString(string sidProtector) {
        SecurityIdentifier securityIdentifier;
        try {
            securityIdentifier = new SecurityIdentifier(sidProtector[4..]);
        } catch {
            return sidProtector;
        }
        NTAccount nTAccount;
        try {
            nTAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));
        } catch {
            return securityIdentifier.ToString();
        }
        string text = nTAccount.ToString();
        return text;
    }
}