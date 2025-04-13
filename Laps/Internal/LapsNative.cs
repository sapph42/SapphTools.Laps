using System;
using System.Runtime.InteropServices;

namespace SapphTools.Laps.Internal;
internal static class LapsNative {
    #region Structs
    public enum COMPUTER_NAME_FORMAT {
        ComputerNameNetBIOS,
        ComputerNameDnsHostname,
        ComputerNameDnsDomain,
        ComputerNameDnsFullyQualified,
        ComputerNamePhysicalNetBIOS,
        ComputerNamePhysicalDnsHostname,
        ComputerNamePhysicalDnsDomain,
        ComputerNamePhysicalDnsFullyQualified,
        ComputerNameMax
    }
    #endregion Structs
    #region Imports

    [DllImport("lapsutil.dll", EntryPoint = "DecryptNormalModeW")]
    public static extern uint DecryptNormalMode(IntPtr hDecryptionIdentityToken, IntPtr pbData, uint cbData, uint ulFlags, out IntPtr pbDecryptedData, out uint cbDecryptedData);

    [DllImport("lapsutil.dll", EntryPoint = "GetSidProtectionStringW", CharSet = CharSet.Unicode)]
    public static extern uint GetSidProtectionString(IntPtr pbData, uint cbData, out uint pSecondaryStatus, out string pszSidProtectionString);
    #endregion Imports
}