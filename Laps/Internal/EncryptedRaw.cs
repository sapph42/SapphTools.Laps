using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

#nullable enable
#pragma warning disable CS0649
namespace SapphTools.Laps.Internal;
[DataContract]
internal class EncryptedRaw {
    [DataMember(Name = "n")]
    public string? AccountName { get; internal set; } = null;

    [DataMember(Name = "t")]
    public string? UpdateTimestamp { get; internal set; } = null;

    [DataMember(Name = "p")]
    public string? Password { get; internal set; } = null;
    public static EncryptedRaw? Parse(string json) {
        DataContractJsonSerializer dataContractJsonSerializer = new(typeof(EncryptedRaw));
        using MemoryStream stream = new(Encoding.UTF8.GetBytes(json));
        return dataContractJsonSerializer.ReadObject(stream) as EncryptedRaw;
    }
}
#pragma warning restore CS0649