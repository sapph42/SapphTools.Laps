namespace SapphTools.Laps.Internal;
internal readonly struct ForestInfo {
    public readonly string ForestDnsName;
    public readonly string RootDomainNamingContext;
    public readonly string ConfigurationNamingContext;
    public readonly string SchemaNamingContext;
    public readonly string SchemaNamingMaster;
    public readonly int ForestFunctionalLevel;

    public ForestInfo(
        string rootDomainDnsHostName,
        string rootDomainNamingContext,
        string configurationNamingContext,
        string schemaNamingContext,
        string schemaNamingMaster,
        int forestFunctionalLevel) {
        ForestDnsName = rootDomainDnsHostName;
        RootDomainNamingContext = rootDomainNamingContext;
        ConfigurationNamingContext = configurationNamingContext;
        SchemaNamingContext = schemaNamingContext;
        SchemaNamingMaster = schemaNamingMaster;
        ForestFunctionalLevel = forestFunctionalLevel;
    }
}