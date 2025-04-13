using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SapphTools.Laps.Internal;
internal readonly struct EncryptedPasswordAttributePrefixInfo {
    public const uint PrefixInfoLength = 16u;
    public readonly uint UpperDateTimeStamp;
    public readonly uint LowerDateTimeStamp;
    public readonly uint EncryptedBufferSize;
    public readonly uint FlagsReserved;
    public readonly DateTime UpdateTimeStampUTC;
    public static EncryptedPasswordAttributePrefixInfo ParseFromBuffer(byte[] buffer) {
        byte[] converter = new byte[4];
        uint[] attribPrefix = new uint[4];
        if ((long)buffer.Length <= 16L) {
            throw new ArgumentException("Buffer not big enough");
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                converter[j] = buffer[i * 4 + j];
            }
            attribPrefix[i] = BitConverter.ToUInt32(converter, 0);
        }
        return new EncryptedPasswordAttributePrefixInfo(attribPrefix[0], attribPrefix[1], attribPrefix[2], attribPrefix[3]);
    }
    private static ulong ConvertTwoUIntsToULong(uint high, uint low) {
        return ((ulong)high << 32) | low;
    }
    private EncryptedPasswordAttributePrefixInfo(uint upperDateTimeStamp, uint lowerDateTimeStamp, uint encryptedBufferSize, uint flagsReserved) {
        UpperDateTimeStamp = upperDateTimeStamp;
        LowerDateTimeStamp = lowerDateTimeStamp;
        EncryptedBufferSize = encryptedBufferSize;
        FlagsReserved = flagsReserved;
        long fileTime = (long)ConvertTwoUIntsToULong(upperDateTimeStamp, lowerDateTimeStamp);
        UpdateTimeStampUTC = DateTime.FromFileTimeUtc(fileTime);
    }
}