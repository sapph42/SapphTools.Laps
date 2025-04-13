using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
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
        credential2 = principal.IsInRole(WindowsBuiltInRole.Administrator)
            ? CredentialCache.DefaultNetworkCredentials
            : throw new LapsException("Must run elevated!");
        LdapConnection result = !string.IsNullOrEmpty(DomainController) && port.HasValue
            ? GetLdapServerConnection(DomainController!, port, credential2)
            : !string.IsNullOrEmpty(Domain)
                ? GetLdapConnection(Domain, writable: true, credential2)
                : GetLdapConnection(null, writable: true, credential2);
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
            AllocateNativeBuffer(encryptedData, out pbBuffer, out uint cbBuffer);
            num = DecryptNormalMode(hDecryptionToken, pbBuffer, cbBuffer, 0u, out pbDecryptedData, out uint cbDecryptedData);
            if (num != 0) {
                return num;
            }
            AllocateManagedBuffer(pbDecryptedData, cbDecryptedData, out byte[]? bytes);
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
            AllocateNativeBuffer(encryptedData, out pbBuffer, out uint cbBuffer);
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
        string filter;
        if (Identity.StartsWith("CN=", StringComparison.InvariantCultureIgnoreCase)) {
            string escapedDn = EscapeDNForFilter(Identity);
            filter = string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "distinguishedName", escapedDn);
        } else {
            filter = Identity[^1] == '$'
                ? string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "samAccountName", Identity)
                : Identity.Contains('.')
                            ? string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "dnsHostName", Identity)
                            : string.Format(CultureInfo.InvariantCulture, "(&(objectClass={0})({1}={2}))", "computer", "name", Identity);
        }
        SearchRequest searchRequest = new() {
            DistinguishedName = ldapConnectionInfo.Domain.DomainNC,
            Filter = filter,
            Scope = SearchScope.Subtree
        };
        searchRequest.Attributes.AddRange(value);
        SearchResponse? searchResponse = ldapConn.SendRequest(searchRequest) as SearchResponse;
        if (searchResponse is not null && searchResponse.Entries.Count != 1) {
            string exceptionText;
            if (searchResponse.Entries.Count == 0) {
                exceptionText = $"Failed to find the '{Identity}' computer in AD";
            } else {
                StringBuilder stringBuilder = new();
                exceptionText = $"Found multiple ({searchResponse.Entries.Count}) results  for the target '{Identity}' identity in AD:";
                stringBuilder.AppendLine(exceptionText);
                for (int i = 0; i < searchResponse.Entries.Count; i++) {
                    SearchResultEntry searchResultEntry = searchResponse.Entries[i];
                    stringBuilder.AppendLine(searchResultEntry.DistinguishedName);
                }
            }
            throw new LapsException(exceptionText);
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
        const uint DS_RETURN_DNS_NAME = 0x40000010;
        const uint DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010;
        const uint DS_IS_DNS_NAME = 0x1000;
        uint flags = DS_RETURN_DNS_NAME | DS_DIRECTORY_SERVICE_REQUIRED;
        if (writable) {
            flags |= DS_IS_DNS_NAME;
        }
        DCLocator dCLocatorInfo = DCLocator.LocateDCNoThrow(null, domainName, null, flags)
            ?? throw new LapsException($"Failed to locate a domain controller in the '{domainName}' domain");

        return GetConnectionWorker(dCLocatorInfo.DomainControllerName, null, credential);
    }
    public static LdapConnectionInfo GetLdapConnectionInfo(LdapConnection ldapConn) {
        var baseRequest = new SearchRequest {
            Scope = SearchScope.Base,
            Attributes =
            {
            "configurationNamingContext",
            "defaultNamingContext",
            "dnsHostName",
            "rootDomainNamingContext",
            "schemaNamingContext",
            "domainControllerFunctionality",
            "domainFunctionality",
            "forestFunctionality",
            "supportedCapabilities"
        }
        };

        var rootResponse = (SearchResponse)ldapConn.SendRequest(baseRequest);
        var entry = rootResponse.Entries[0];

        string configurationNC = GetSingleString(entry, "configurationNamingContext");
        string defaultNC = GetSingleString(entry, "defaultNamingContext");
        string dnsHostNameDC = GetSingleString(entry, "dnsHostName");
        string rootDomainNC = GetSingleString(entry, "rootDomainNamingContext");
        string schemaNC = GetSingleString(entry, "schemaNamingContext");

        int dcFunctionalLevel = ParseIntAttribute(entry, "domainControllerFunctionality");
        int domainFunctionalLevel = ParseIntAttribute(entry, "domainFunctionality");
        int forestFunctionalLevel = ParseIntAttribute(entry, "forestFunctionality");

        bool isRODC = GetStringListFromBytes(entry.Attributes, "supportedCapabilities")
            .Any(v => StringComparer.OrdinalIgnoreCase.Equals(v, "1.2.840.113556.1.4.1920"));

        string domainDnsHostName = LookupDnsRoot(ldapConn, configurationNC, defaultNC);
        string rootDomainDnsHostName = LookupDnsRoot(ldapConn, configurationNC, rootDomainNC);
        string schemaNamingMaster = LookupSchemaNamingMaster(ldapConn, schemaNC);

        var forestInfo = new ForestInfo(rootDomainDnsHostName, rootDomainNC, configurationNC, schemaNC, schemaNamingMaster, forestFunctionalLevel);
        var domainInfo = new DomainInfo(domainDnsHostName, defaultNC, domainFunctionalLevel);
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
    private static string GetSingleString(SearchResultEntry entry, string attributeName) {
        return (string)entry.Attributes[attributeName].GetValues(typeof(string))[0];
    }
    private static IEnumerable<string> GetStringListFromBytes(SearchResultAttributeCollection attributes, string attrName) {
        return attributes[attrName]
            .GetValues(typeof(byte[]))
            .Cast<byte[]>()
            .Select(b => Encoding.UTF8.GetString(b));
    }
    private static string LookupDnsRoot(LdapConnection conn, string configNC, string ncName) {
        string partitionDN = $"CN=Partitions,{configNC}";
        string filter = $"(&(objectClass=crossRef)(nCName={ncName}))";
        var request = new SearchRequest(partitionDN, filter, SearchScope.OneLevel, "dnsRoot");

        var response = (SearchResponse)conn.SendRequest(request);
        return GetSingleString(response.Entries[0], "dnsRoot");
    }
    private static string LookupSchemaNamingMaster(LdapConnection conn, string schemaNC) {
        var roleOwnerRequest = new SearchRequest(schemaNC, "(objectClass=*)", SearchScope.Base, "fSMORoleOwner");
        var roleOwnerEntry = (SearchResponse)conn.SendRequest(roleOwnerRequest);
        string ownerDN = GetSingleString(roleOwnerEntry.Entries[0], "fSMORoleOwner");
        string serverDN = ownerDN["CN=NTDS Settings,".Length..];

        var dnsRequest = new SearchRequest(serverDN, "(objectClass=*)", SearchScope.Base, "dnsHostName");
        var dnsEntry = (SearchResponse)conn.SendRequest(dnsRequest);
        return GetSingleString(dnsEntry.Entries[0], "dnsHostName");
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
    private static int ParseIntAttribute(SearchResultEntry entry, string attributeName) {
        string value = (string)entry.Attributes[attributeName].GetValues(typeof(string))[0];
        return string.IsNullOrEmpty(value) ? 0 : int.Parse(value, NumberFormatInfo.InvariantInfo);
    }
    public static string QueryLocalComputerName(COMPUTER_NAME_FORMAT nameFormat) {
        StringBuilder stringBuilder = new(300);
        int lpnSize = 300;
        return !GetComputerNameEx(nameFormat, stringBuilder, ref lpnSize)
            ? throw new InvalidOperationException("Unable to query the local computer name")
            : stringBuilder.ToString();
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