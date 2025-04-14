#nullable enable
namespace SapphTools.Laps.Internal;
internal readonly struct EncryptedState {
    public readonly string AuthorizedDecryptorSid;
    public readonly EncryptedPrefix PrefixInfo;
    public readonly EncryptedInner? InnerState;
    public readonly byte[] TrailingBytes;

    public EncryptedState(
        string authorizedDecryptorSid,
        EncryptedPrefix prefixInfo,
        EncryptedInner? innerState,
        byte[] trailingBytes) {
        AuthorizedDecryptorSid = authorizedDecryptorSid;
        PrefixInfo = prefixInfo;
        InnerState = innerState;
        TrailingBytes = trailingBytes;
    }
}