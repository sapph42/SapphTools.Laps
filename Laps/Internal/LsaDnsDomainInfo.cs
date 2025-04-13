using System;
using System.Security.Principal;
using static SapphTools.Laps.Internal.OSNative;

#nullable enable
namespace SapphTools.Laps.Internal;
internal readonly struct LsaDnsDomainInfo {
    public readonly string Name;
    public readonly string DnsDomainName;
    public readonly string DnsForestName;
    public readonly Guid DomainGuid;
    public readonly string? Sid;

    public LsaDnsDomainInfo(string name, string dnsDomainName, string dnsForestName, Guid domainGuid, string? sid) {
        Name = name;
        DnsDomainName = dnsDomainName;
        DnsForestName = dnsForestName;
        DomainGuid = domainGuid;
        Sid = sid;
    }

    public LsaDnsDomainInfo(POLICY_DNS_DOMAIN_INFO domainInfo)
        : this(
            domainInfo.Name.ToString(),
            domainInfo.DnsDomainName.ToString(),
            domainInfo.DnsForestName.ToString(),
            domainInfo.DomainGuid,
            domainInfo.Sid != IntPtr.Zero
                ? new SecurityIdentifier(domainInfo.Sid).ToString()
                : null) { }
}