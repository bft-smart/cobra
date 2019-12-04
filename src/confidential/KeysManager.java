package confidential;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import static confidential.Configuration.defaultKeys;
import static confidential.Configuration.shareEncryptionAlgorithm;

/**
 * @author Robin
 */
public class KeysManager {
    private Key defaultKey;

    public KeysManager() {
        defaultKey = new SecretKeySpec(defaultKeys[0].toByteArray(),
            shareEncryptionAlgorithm);
    }

    public Key getEncryptionKeyFor(int id) {
        return defaultKey;
    }

    public Key getDecryptionKeyFor(int id) {
        return defaultKey;
    }
}
