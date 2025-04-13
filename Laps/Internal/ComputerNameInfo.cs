#nullable enable
namespace SapphTools.Laps.Internal;
internal readonly struct ComputerNameInfo {
    public readonly string Name;
    public readonly string DistinguishedName;
    public readonly string SamAccountName;
    public readonly string DnsHostName;

    public ComputerNameInfo(string? name, string? distinguishedName, string? samAccountName, string? dnsHostName) {
        Name = name ?? string.Empty;
        DistinguishedName = distinguishedName ?? string.Empty;
        SamAccountName = samAccountName ?? string.Empty;
        DnsHostName = dnsHostName ?? string.Empty;
    }

    public override string ToString() {
        return $"Name:{Name} SamAccountName:{SamAccountName} DnsHostName:{DnsHostName} DistinguishedName:'{DistinguishedName}'";
    }
}