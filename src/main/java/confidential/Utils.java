package confidential;

import java.io.BufferedInputStream;
import java.io.IOException;

/**
 * @author Robin
 */
public class Utils {

    public static byte[] toBytes(int number) {
        byte[] result = new byte[4];
        result[3] = (byte) number;
        number >>= 8;
        result[2] = (byte) number;
        number >>= 8;
        result[1] = (byte) number;
        number >>= 8;
        result[0] = (byte) number;

        return result;
    }

    public static int toNumber(byte[] numberInBytes) {
        int number = Byte.toUnsignedInt(numberInBytes[0]);
        number <<= 8;
        number |= Byte.toUnsignedInt(numberInBytes[1]);
        number <<= 8;
        number |= Byte.toUnsignedInt(numberInBytes[2]);
        number <<= 8;
        number |= Byte.toUnsignedInt(numberInBytes[3]);
        return number;
    }

    public static byte[] readNBytes(int n, BufferedInputStream stream) throws IOException {
        byte[] result = new byte[n];
        int offset = 0;
        while (n > 0) {
            int len = stream.read(result, offset, n);
            offset += len;
            n -= len;
        }

        return result;
    }

    public static boolean isIn(int n, int[] ns) {
        for (int i : ns) {
            if (i == n)
                return true;
        }
        return false;
    }
}
