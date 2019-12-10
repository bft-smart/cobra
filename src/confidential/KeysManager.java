package confidential;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;

/**
 * @author Robin
 */
public class KeysManager {
    private static final BigInteger plainDefaultKey = new BigInteger(
            "937810634060551071826485204471949219646466658841719067506");
    private Key defaultKey;

    public KeysManager() {
        defaultKey = new SecretKeySpec(plainDefaultKey.toByteArray(),
            Configuration.getInstance().getShareEncryptionAlgorithm());
    }

    public Key getEncryptionKeyFor(int id) {
        return defaultKey;
    }

    public Key getDecryptionKeyFor(int id) {
        return defaultKey;
    }
}
