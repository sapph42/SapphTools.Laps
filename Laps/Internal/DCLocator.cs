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
    public DCLocator(DC_INFO info) : this(
        info.DomainControllerName[2..],
        info.DomainControllerAddress,
        info.DomainControllerAddressType,
        info.DomainGuid,
        info.DomainDnsName,
        info.ForestDnsName,
        info.Flags,
        info.DcSiteName,
        info.ClientSiteName
    ) { }
    public static DCLocator? LocateDCNoThrow(string? ComputerName, string? DomainName, string? SiteName, uint Flags) {
        const uint DS_RETURN_FLAT_NAME = 0x80000000u;
        const uint DS_RETURN_DNS_NAME = 0x40000000;
        if ((Flags & DS_RETURN_FLAT_NAME) != 0) {
            throw new ArgumentException("Should never request flat name");
        }
        Flags |= DS_RETURN_DNS_NAME;
        ComputerName ??= string.Empty;
        DomainName ??= string.Empty;
        SiteName ??= string.Empty;
        nint dcInfoPtr;
        try {
            if (DsGetDcName(ComputerName, DomainName, IntPtr.Zero, SiteName, Flags, out dcInfoPtr) != 0) {
                return null;
            }
        } catch {
            return null;
        }
        try {
            DC_INFO? dcInfo = (DC_INFO?)Marshal.PtrToStructure(dcInfoPtr, typeof(DC_INFO));
            return dcInfo is null ? null : new DCLocator(dcInfo.Value);
        } catch (Exception) {
            return null;
        } finally {
            NetApiBufferFree(dcInfoPtr);
        }
    }
}