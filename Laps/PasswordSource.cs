namespace SapphTools.Laps;
/// <summary>
/// Identifies the source or type of the LAPS password that was retrieved.
/// </summary>
public enum PasswordSource {
    /// <summary>
    /// No password was found in the LAPS attributes for the account.
    /// </summary>
    PasswordMissing,

    /// <summary>
    /// The password was retrieved from the legacy ms-Mcs-AdmPwd attribute (cleartext).
    /// </summary>
    LegacyLapsCleartextPassword,

    /// <summary>
    /// The password was retrieved from the new cleartext LAPS v2 attribute (msLAPS-Password).
    /// </summary>
    CleartextPassword,

    /// <summary>
    /// The password was retrieved from the encrypted LAPS v2 attribute (msLAPS-EncryptedPassword).
    /// </summary>
    EncryptedPassword,

    /// <summary>
    /// The password was retrieved from the encrypted password history attribute (msLAPS-EncryptedPasswordHistory).
    /// </summary>
    EncryptedPasswordHistory,

    /// <summary>
    /// The password was retrieved from the encrypted DSRM password attribute (msLAPS-EncryptedDSRMPassword).
    /// </summary>
    EncryptedDSRMPassword,

    /// <summary>
    /// The password was retrieved from the encrypted DSRM password history attribute (msLAPS-EncryptedDSRMPasswordHistory).
    /// </summary>
    EncryptedDSRMPasswordHistory
}