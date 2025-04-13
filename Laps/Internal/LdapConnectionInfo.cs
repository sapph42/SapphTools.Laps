namespace SapphTools.Laps.Internal;
internal readonly struct LdapConnectionInfo {
    public readonly string DnsHostNameDC;
    public readonly int DCFunctionalLevel;
    public readonly bool IsRODC;
    public readonly DomainInfo Domain;
    public readonly ForestInfo Forest;

    public LdapConnectionInfo(
        string dnsHostNameDC,
        int dcFunctionalLevel,
        bool isRODC,
        ForestInfo forestInfo,
        DomainInfo domainInfo) {
        DnsHostNameDC = dnsHostNameDC;
        DCFunctionalLevel = dcFunctionalLevel;
        IsRODC = isRODC;
        Domain = domainInfo;
        Forest = forestInfo;
    }
}