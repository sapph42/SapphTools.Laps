using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using static SapphTools.Laps.Internal.OSNative;

namespace SapphTools.Laps.Internal;
internal static class LsaPolicy {
    private enum QueryType : uint {
        Domain = 3u,
        Account = 5u,
        DomainInfo = 12u
    }
    public static LsaDnsDomainInfo QueryDns() {
        IntPtr intPtr = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try {
            intPtr = GetLocalLsaPolicyHandle();
            if (intPtr == IntPtr.Zero) {
                throw new Exception("GetLocalLsaPolicyHandle failed");
            }
            if (LsaQueryInformationPolicy(intPtr, (uint)QueryType.DomainInfo, out buffer) != 0) {
                throw new Exception("LsaQueryInformationPolicy(LsaDnsDomainInfo) failed");
            }
            DnsDomainPolicy? dnsDomainPolicy = (DnsDomainPolicy?)Marshal.PtrToStructure(buffer, typeof(DnsDomainPolicy));
            return new LsaDnsDomainInfo(dnsDomainPolicy!.Value);
        } finally {
            if (buffer != IntPtr.Zero) {
                LsaFreeMemory(buffer);
            }
            if (intPtr != IntPtr.Zero) {
                LsaClose(intPtr);
            }
        }
    }

    public static LsaDomainInfo QueryAccount() {
        return GenericQuery((uint)QueryType.Account);
    }
    public static LsaDomainInfo QueryDomain() {
        return GenericQuery((uint)QueryType.Domain);
    }
    private static LsaDomainInfo GenericQuery(uint infoClass) {
        IntPtr intPtr = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try {
            intPtr = GetLocalLsaPolicyHandle();
            if (intPtr == IntPtr.Zero) {
                throw new Exception("GetLocalLsaPolicyHandle failed");
            }
            if (LsaQueryInformationPolicy(intPtr, infoClass, out buffer) != 0 || buffer == IntPtr.Zero) {
                throw new Exception("LsaQueryInformationPolicy(PolicyAccountDomainInformation) failed");
            }
            DomainPolicy domainPolicy = (DomainPolicy)Marshal.PtrToStructure(buffer, typeof(DomainPolicy))!;
            return new LsaDomainInfo(
                domainPolicy.DomainName.ToString(),
                domainPolicy.DomainSid != IntPtr.Zero
                    ? new SecurityIdentifier(domainPolicy.DomainSid).ToString()
                    : null
            );
        } finally {
            if (buffer != IntPtr.Zero) {
                LsaFreeMemory(buffer);
            }
            if (intPtr != IntPtr.Zero) {
                LsaClose(intPtr);
            }
        }
    }
    private static IntPtr GetLocalLsaPolicyHandle() {
        uint desiredAccess = 1u;
        LsaString SystemName = default;
        LsaAttribs lsaAttribs = default;
        return LsaNtStatusToWinError(LsaOpenPolicy(ref SystemName, ref lsaAttribs, desiredAccess, out IntPtr PolicyHandle)) == 0
            ? PolicyHandle
            : throw new Exception("LsaOpenPolicy failed"); 
    }
}
