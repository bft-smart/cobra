package confidential;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Robin
 */
public class KeysManager {
    private static final BigInteger plainDefaultKey = new BigInteger(
            "937810634060551071826485204471949219646466658841719067506");
    private static final BigInteger defaultPrivateKey = new BigInteger("42400449615825239949034251209721392312410047603504363169820785445001651662277979956363202055358334835505599710621490050536674602129719769891539502059662999908627");
    private static final BigInteger defaultPublicKey = new BigInteger("266672905649514438536656557520920847633091448666612895350298546148420402022892748010271724159740115359102719623331796431043515450604764280501191614568816759185080314532524410878790809621061999788641642341000049746508164");

    private final Key defaultSymmetricKey;
    private PublicKey[] signingPublicKey;
    private PrivateKey mySigningPrivateKey;

    public KeysManager() {
        defaultSymmetricKey = new SecretKeySpec(plainDefaultKey.toByteArray(),
            Configuration.getInstance().getShareEncryptionAlgorithm());
        try {
            signingPublicKey = new PublicKey[1];
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            for (int i = 0; i < signingPublicKey.length; i++) {
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(defaultPublicKey.toByteArray());
                signingPublicKey[i] = keyFactory.generatePublic(publicKeySpec);
            }
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(defaultPrivateKey.toByteArray());
            mySigningPrivateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public Key getEncryptionKeyFor(int id) {
        return defaultSymmetricKey;
    }

    public Key getDecryptionKeyFor(int id) {
        return defaultSymmetricKey;
    }

    public PublicKey getSigningPublicKeyFor(int id) {
        return signingPublicKey[id % signingPublicKey.length];
    }

    public PrivateKey getSigningKey() {
        return mySigningPrivateKey;
    }
}
