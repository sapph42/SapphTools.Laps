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

    [DllImport("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\LAPS\\lapsutil.dll")]
    public static extern uint DecryptNormalMode(IntPtr hDecryptionIdentityToken, IntPtr pbData, uint cbData, uint ulFlags, out IntPtr pbDecryptedData, out uint cbDecryptedData);

    [DllImport("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\LAPS\\lapsutil.dll", CharSet = CharSet.Unicode)]
    public static extern uint LogonWithCredentials(string domain, string user, string password, out IntPtr hToken);
    
    [DllImport("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\LAPS\\lapsutil.dll", CharSet = CharSet.Unicode)]
    public static extern uint GetSidProtectionString(IntPtr pbData, uint cbData, out uint pSecondaryStatus, out string pszSidProtectionString);
    #endregion Imports
}