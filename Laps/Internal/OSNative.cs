using System;
using System.Runtime.InteropServices;

namespace SapphTools.Laps.Internal;
internal static partial class OSNative {
    #region Structs
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DC_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string DomainControllerName;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string DomainControllerAddress;

        public uint DomainControllerAddressType;

        public Guid DomainGuid;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string DomainDnsName;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string ForestDnsName;

        public uint Flags;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string DcSiteName;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string ClientSiteName;
    }
    public struct LsaAttribs {
        public int Length;

        public IntPtr RootDirectory;

        public LsaString ObjectName;

        public uint Attributes;

        public IntPtr SecurityDescriptor;

        public IntPtr SecurityQualityOfService;
    }
    public static LsaAttribs EmptyAttribs() {
        return default;
    }
    public struct LsaString : IDisposable {
        public ushort Length;

        public ushort MaximumLength;

        public IntPtr Buffer;

        public void SetTo(string str) {
            Buffer = Marshal.StringToHGlobalUni(str);
            Length = (ushort)(str.Length * 2);
            MaximumLength = (ushort)(Length + 2);
        }

        public override readonly string ToString() {
            return Marshal.PtrToStringUni(Buffer) ?? string.Empty;
        }

        public void Reset() {
            if (Buffer != IntPtr.Zero) {
                Marshal.FreeHGlobal(Buffer);
            }
            Buffer = IntPtr.Zero;
            Length = 0;
            MaximumLength = 0;
        }

        public void Dispose() {
            Reset();
        }
    }
    public static LsaString EmptyString() {
        return default;
    }
    public struct DomainPolicy {
        public LsaString DomainName { get; set; }

        public IntPtr DomainSid { get; set; }
    }
    internal struct DnsDomainPolicy {
        public LsaString Name { get; set; }

        public LsaString DnsDomainName { get; set; }

        public LsaString DnsForestName { get; set; }

        public Guid DomainGuid { get; set; }

        public IntPtr Sid { get; set; }
    }
    #endregion Structs
    #region Imports
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("netapi32.dll", EntryPoint = "DsGetDcNameW", SetLastError = true, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    internal static extern int DsGetDcName(
        [MarshalAs(UnmanagedType.LPWStr)] string ComputerName,
        [MarshalAs(UnmanagedType.LPWStr)] string DomainName,
        IntPtr DomainGuid,
        [MarshalAs(UnmanagedType.LPWStr)] string SiteName,
        uint Flags,
        out IntPtr pDOMAIN_CONTROLLER_INFO);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int LsaClose(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int LsaFreeMemory(IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint LsaNtStatusToWinError(uint status);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint LsaOpenPolicy(
        ref LsaString SystemName,
        ref LsaAttribs ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint LsaQueryInformationPolicy(
        IntPtr policyHandle,
        uint informationClass,
        out IntPtr buffer);

    [DllImport("netapi32.dll", SetLastError = true)]
    public static extern int NetApiBufferFree(IntPtr Buffer);
    #endregion Imports
}