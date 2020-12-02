package confidential;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author Robin
 */
public class KeysManager {
    private static final BigInteger plainDefaultKey = new BigInteger(
            "937810634060551071826485204471949219646466658841719067506");
    private final Key defaultKey;
    private final PublicKey[] signingPublicKey;
    private final PrivateKey mySigningPrivateKey;

    public KeysManager() {
        defaultKey = new SecretKeySpec(plainDefaultKey.toByteArray(),
            Configuration.getInstance().getShareEncryptionAlgorithm());
        signingPublicKey = new PublicKey[1];
        for (int i = 0; i < signingPublicKey.length; i++) {
            signingPublicKey[i] = null;
        }
        mySigningPrivateKey = null;
    }

    public Key getEncryptionKeyFor(int id) {
        return defaultKey;
    }

    public Key getDecryptionKeyFor(int id) {
        return defaultKey;
    }

    public PublicKey getSigningPublicKeyFor(int id) {
        return signingPublicKey[id];
    }

    public PrivateKey getSigningKey() {
        return mySigningPrivateKey;
    }
}
