namespace SapphTools.Laps.Internal;
internal readonly struct LocalMachineInfo {
    public readonly string DnsHostName;
    public readonly string NetbiosName;
    public readonly bool RunningOnDC;
    public readonly bool RunningOnRODC;
    public readonly LsaDnsDomainInfo DnsDomainInfo;
    public readonly LsaDomainInfo PrimaryDomainInfo;
    public readonly LsaDomainInfo AccountDomainInfo;

    public LocalMachineInfo(
        string dnsHostName,
        string netbiosName,
        bool runningOnDC,
        bool runningOnRODC,
        LsaDnsDomainInfo lsaDnsDomainInfo,
        LsaDomainInfo lsaPrimaryDomainInfo,
        LsaDomainInfo lsaAccountDomainInfo) {
        DnsHostName = dnsHostName;
        NetbiosName = netbiosName;
        RunningOnDC = runningOnDC;
        RunningOnRODC = runningOnRODC;
        DnsDomainInfo = lsaDnsDomainInfo;
        PrimaryDomainInfo = lsaPrimaryDomainInfo;
        AccountDomainInfo = lsaAccountDomainInfo;
    }
}