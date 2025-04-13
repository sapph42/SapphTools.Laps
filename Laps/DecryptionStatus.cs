namespace SapphTools.Laps;

/// <summary>
/// Indicates the outcome of decrypting a LAPS password.
/// </summary>
public enum DecryptionStatus {
    /// <summary>
    /// Decryption was not attempted or is not applicable (e.g., clear-text password).
    /// </summary>
    NotApplicable,

    /// <summary>
    /// The password was successfully decrypted.
    /// </summary>
    Success,

    /// <summary>
    /// The current user is not authorized to decrypt the password.
    /// </summary>
    Unauthorized,

    /// <summary>
    /// An unexpected error occurred during decryption.
    /// </summary>
    Error
}
