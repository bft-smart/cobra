package confidential.client;

import bftsmart.reconfiguration.views.View;
import confidential.CobraConfidentialityScheme;
import confidential.Configuration;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import static confidential.Configuration.defaultKeys;

public class ClientConfidentialityScheme extends CobraConfidentialityScheme {
    private final Map<BigInteger, Key> keys;

    public ClientConfidentialityScheme(View view) throws SecretSharingException {
        super(view);
        int[] currentViewProcesses = view.getProcesses();
        keys = new HashMap<>(currentViewProcesses.length);

        for (int i = 0; i < currentViewProcesses.length; i++) {
            BigInteger shareholder = getShareholder(currentViewProcesses[i]);
            keys.put(shareholder, new SecretKeySpec(defaultKeys[i].toByteArray(),
                    Configuration.getInstance().getShareEncryptionAlgorithm()));
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
