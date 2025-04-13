#nullable enable
namespace SapphTools.Laps.Internal;
internal readonly struct EncryptedPasswordAttributeState {
    public readonly string AuthorizedDecryptorSid;
    public readonly EncryptedPasswordAttributePrefixInfo PrefixInfo;
    public readonly EncryptedPasswordAttributeInner? InnerState;
    public readonly byte[] TrailingBytes;

    public EncryptedPasswordAttributeState(
        string authorizedDecryptorSid,
        EncryptedPasswordAttributePrefixInfo prefixInfo,
        EncryptedPasswordAttributeInner? innerState,
        byte[] trailingBytes) {
        AuthorizedDecryptorSid = authorizedDecryptorSid;
        PrefixInfo = prefixInfo;
        InnerState = innerState;
        TrailingBytes = trailingBytes;
    }
}