package confidential.client;

import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import static confidential.Configuration.*;

public class ClientConfidentialityScheme {
    private final Map<BigInteger, Key> keys;
    private final VSSFacade vss;

    public ClientConfidentialityScheme(int currentViewF, int[] currentViewProcesses) throws SecretSharingException {
        keys = new HashMap<>(currentViewProcesses.length);
        BigInteger[] shareholders = new BigInteger[currentViewProcesses.length];
        for (int i = 0; i < currentViewProcesses.length; i++) {
            shareholders[i] = BigInteger.valueOf(currentViewProcesses[i] + 1);
            keys.put(shareholders[i], new SecretKeySpec(defaultKeys[i].toByteArray(), shareEncryptionAlgorithm));
        }
        vss = new VSSFacade(p, generator, field, currentViewF, shareholders, dataEncryptionAlgorithm,
                dataEncryptionKeySize, shareEncryptionAlgorithm);
    }

    public PrivatePublishedShares share(byte[] secret) throws SecretSharingException {
        return vss.share(secret, keys);
    }


    public byte[] combine(OpenPublishedShares shares) throws SecretSharingException {
        return vss.combine(shares);
    }
}
