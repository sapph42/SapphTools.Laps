namespace SapphTools.Laps.Internal;
internal readonly struct DomainInfo {
    public readonly string DomainDnsName;
    public readonly string DomainNC;
    public readonly int DomainFunctionalLevel;

    public DomainInfo(string domainDnsHostName, string domainNC, int domainFunctionalLevel) {
        DomainDnsName = domainDnsHostName;
        DomainNC = domainNC;
        DomainFunctionalLevel = domainFunctionalLevel;
    }
}