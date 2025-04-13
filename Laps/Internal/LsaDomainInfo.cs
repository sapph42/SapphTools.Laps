#nullable enable
namespace SapphTools.Laps.Internal;
internal readonly struct LsaDomainInfo {
    public readonly string Name;
    public readonly string? Sid;
    public LsaDomainInfo(string name, string? sid) {
        Name = name;
        Sid = sid;
    }
}