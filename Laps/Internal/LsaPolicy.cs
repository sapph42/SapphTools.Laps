using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using static SapphTools.Laps.Internal.OSNative;

namespace SapphTools.Laps.Internal;
internal static class LsaPolicy {
    public static LsaDnsDomainInfo QueryDnsDomainInfo() {
        IntPtr intPtr = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try {
            intPtr = GetLocalLsaPolicyHandle();
            if (intPtr == IntPtr.Zero) {
                throw new Exception("GetLocalLsaPolicyHandle failed");
            }
            if (LsaQueryInformationPolicy(intPtr, 12u, out buffer) != 0) {
                throw new Exception("LsaQueryInformationPolicy(PolicyAccountDomainInformation) failed");
            }
            POLICY_DNS_DOMAIN_INFO? pOLICY_DNS_DOMAIN_INFO = (POLICY_DNS_DOMAIN_INFO?)Marshal.PtrToStructure(buffer, typeof(POLICY_DNS_DOMAIN_INFO));
            return new LsaDnsDomainInfo(pOLICY_DNS_DOMAIN_INFO!.Value);
        } finally {
            if (buffer != IntPtr.Zero) {
                LsaFreeMemory(buffer);
            }
            if (intPtr != IntPtr.Zero) {
                LsaClose(intPtr);
            }
        }
    }

    public static LsaDomainInfo QueryAccountDomainInfo() {
        IntPtr intPtr = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try {
            intPtr = GetLocalLsaPolicyHandle();
            if (intPtr == IntPtr.Zero) {
                throw new Exception("GetLocalLsaPolicyHandle failed");
            }
            if (LsaQueryInformationPolicy(intPtr, 5u, out buffer) != 0 || buffer == IntPtr.Zero) {
                throw new Exception("LsaQueryInformationPolicy(PolicyAccountDomainInformation) failed");
            }
            POLICY_DOMAIN_INFO pOLICY_ACCOUNT_DOMAIN_INFO = (POLICY_DOMAIN_INFO)Marshal.PtrToStructure(buffer, typeof(POLICY_DOMAIN_INFO))!;
            return new LsaDomainInfo(
                pOLICY_ACCOUNT_DOMAIN_INFO.DomainName.ToString(),
                pOLICY_ACCOUNT_DOMAIN_INFO.DomainSid != IntPtr.Zero
                    ? new SecurityIdentifier(pOLICY_ACCOUNT_DOMAIN_INFO.DomainSid).ToString()
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

    public static LsaDomainInfo QueryPrimaryDomainInfo() {
        IntPtr intPtr = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        try {
            intPtr = GetLocalLsaPolicyHandle();
            if (intPtr == IntPtr.Zero) {
                throw new Exception("GetLocalLsaPolicyHandle failed");
            }
            if (LsaQueryInformationPolicy(intPtr, 3u, out buffer) != 0 || buffer == IntPtr.Zero) {
                throw new Exception("LsaQueryInformationPolicy(PolicyPrimaryDomainInformation) failed");
            }
            POLICY_DOMAIN_INFO pOLICY_PRIMARY_DOMAIN_INFO = (POLICY_DOMAIN_INFO)Marshal.PtrToStructure(buffer, typeof(POLICY_DOMAIN_INFO))!;
            return new LsaDomainInfo(pOLICY_PRIMARY_DOMAIN_INFO.DomainName.ToString(),
                pOLICY_PRIMARY_DOMAIN_INFO.DomainSid != IntPtr.Zero
                    ? new SecurityIdentifier(pOLICY_PRIMARY_DOMAIN_INFO.DomainSid).ToString()
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
        LSA_UNICODE_STRING SystemName = default;
        IntPtr PolicyHandle = IntPtr.Zero;
        LSA_OBJECT_ATTRIBUTES lSA_OBJECT_ATTRIBUTES = default;
        lSA_OBJECT_ATTRIBUTES.RootDirectory = IntPtr.Zero;
        lSA_OBJECT_ATTRIBUTES.SecurityDescriptor = IntPtr.Zero;
        lSA_OBJECT_ATTRIBUTES.SecurityQualityOfService = IntPtr.Zero;
        LSA_OBJECT_ATTRIBUTES ObjectAttributes = lSA_OBJECT_ATTRIBUTES;
        return LsaNtStatusToWinError(LsaOpenPolicy(ref SystemName, ref ObjectAttributes, desiredAccess, out PolicyHandle)) != 0
            ? throw new Exception("LsaOpenPolicy failed")
            : PolicyHandle;
    }
}
