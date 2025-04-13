using System;
using System.Runtime.InteropServices;
using static SapphTools.Laps.Internal.OSNative;

#nullable enable
namespace SapphTools.Laps.Internal;
internal class DCLocator {
    public string DomainControllerName { get; }
    public string DomainControllerAddress { get; }
    public uint DomainControllerAddressType { get; }
    public Guid DomainGuid { get; }
    public string DomainDnsName { get; }
    public string ForestDnsName { get; }
    public uint Flags { get; }
    public string DcSiteName { get; }
    public string ClientSiteName { get; }
    private DCLocator(string domainControllerName, string domainControllerAddress, uint domainControllerAddressType, Guid domainGuid, string domainDnsName, string forestDnsName, uint flags, string dcSiteName, string clientSiteName) {
        DomainControllerName = domainControllerName;
        DomainControllerAddress = domainControllerAddress;
        DomainControllerAddressType = domainControllerAddressType;
        DomainGuid = domainGuid;
        DomainDnsName = domainDnsName;
        ForestDnsName = forestDnsName;
        Flags = flags;
        DcSiteName = dcSiteName;
        ClientSiteName = clientSiteName;
    }
    public DCLocator(DOMAIN_CONTROLLER_INFO info) : this(
        info.DomainControllerName.Substring(2),
        info.DomainControllerAddress,
        info.DomainControllerAddressType,
        info.DomainGuid,
        info.DomainDnsName,
        info.ForestDnsName,
        info.Flags,
        info.DcSiteName,
        info.ClientSiteName
    ) { }
    public static DCLocator LocateDC(string ComputerName, string DomainName, string SiteName, uint Flags) {
        return LocateDCNoThrow(ComputerName, DomainName, SiteName, Flags) ?? throw new Exception("DClocator failed");
    }
    public static DCLocator? LocateDCNoThrow(string? ComputerName, string? DomainName, string? SiteName, uint Flags) {
        if ((Flags & 0x80000000u) != 0) {
            throw new ArgumentException("Should never request flat name");
        }
        Flags |= 0x40000000;
        ComputerName ??= string.Empty;
        DomainName ??= string.Empty;
        SiteName ??= string.Empty;
        nint pDOMAIN_CONTROLLER_INFO;
        try {
            if (DsGetDcName(ComputerName, DomainName, IntPtr.Zero, SiteName, Flags, out pDOMAIN_CONTROLLER_INFO) != 0) {
                return null;
            }
        } catch {
            return null;
        }
        try {
            DOMAIN_CONTROLLER_INFO? dOMAIN_CONTROLLER_INFO = (DOMAIN_CONTROLLER_INFO?)Marshal.PtrToStructure(pDOMAIN_CONTROLLER_INFO, typeof(DOMAIN_CONTROLLER_INFO));
            return dOMAIN_CONTROLLER_INFO is null ? null : new DCLocator(dOMAIN_CONTROLLER_INFO.Value);
        } catch (Exception) {
            return null;
        } finally {
            NetApiBufferFree(pDOMAIN_CONTROLLER_INFO);
        }
    }
}