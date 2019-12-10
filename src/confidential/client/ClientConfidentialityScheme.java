package confidential.client;

import bftsmart.reconfiguration.views.View;
import confidential.CobraConfidentialityScheme;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;

import java.math.BigInteger;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

public class ClientConfidentialityScheme extends CobraConfidentialityScheme {
    private final Map<BigInteger, Key> keys;

    public ClientConfidentialityScheme(View view) throws SecretSharingException {
        super(view);
        int[] currentViewProcesses = view.getProcesses();
        keys = new HashMap<>(currentViewProcesses.length);

        for (int currentViewProcess : currentViewProcesses) {
            BigInteger shareholder = getShareholder(currentViewProcess);
            Key encryptionKey = keysManager.getEncryptionKeyFor(currentViewProcess);
            keys.put(shareholder, encryptionKey);
        }
    }

    public PrivatePublishedShares share(byte[] secret) throws SecretSharingException {
        return vss.share(secret, keys);
    }

    public byte[] combine(OpenPublishedShares shares) throws SecretSharingException {
        byte[] b = vss.combine(shares);
        if (b == null || b.length == 0)
            System.out.println("Confidential data is null");
        return b;
    }
}
