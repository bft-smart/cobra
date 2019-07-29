package confidential.client;

import bftsmart.reconfiguration.views.View;
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
    private int threshold;

    public ClientConfidentialityScheme(View view) throws SecretSharingException {
        int[] currentViewProcesses = view.getProcesses();
        keys = new HashMap<>(currentViewProcesses.length);
        BigInteger[] shareholders = new BigInteger[currentViewProcesses.length];
        for (int i = 0; i < currentViewProcesses.length; i++) {
            shareholders[i] = BigInteger.valueOf(currentViewProcesses[i] + 1);
            keys.put(shareholders[i], new SecretKeySpec(defaultKeys[i].toByteArray(), shareEncryptionAlgorithm));
        }
        threshold = view.getF();
        vss = new VSSFacade(p, generator, field, shareholders, dataEncryptionAlgorithm,
                dataEncryptionKeySize, shareEncryptionAlgorithm);
    }

    public void updateParameters(View view) throws SecretSharingException {
        threshold = view.getF();
        for (int process : view.getProcesses()) {
            vss.addShareholder(BigInteger.valueOf(process));
        }
    }

    public PrivatePublishedShares share(byte[] secret) throws SecretSharingException {
        return vss.share(threshold, secret, keys);
    }


    public byte[] combine(OpenPublishedShares shares) throws SecretSharingException {
        byte[] b = vss.combine(shares);
        if (b == null || b.length == 0)
            System.out.println("Confidential data is null");
        return b;
    }
}
