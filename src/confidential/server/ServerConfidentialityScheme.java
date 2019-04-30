package confidential.server;

import bftsmart.reconfiguration.views.View;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.VerifiableShare;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;

import static confidential.Configuration.*;

public class ServerConfidentialityScheme {
    private final Key decipheringKey;
    private final BigInteger shareholder;
    private final VSSFacade vss;

    public ServerConfidentialityScheme(int processId, View view) throws SecretSharingException {
        decipheringKey = new SecretKeySpec(defaultKeys[processId].toByteArray(), shareEncryptionAlgorithm);
        shareholder = BigInteger.valueOf(processId + 1);
        int[] currentViewProcesses = view.getProcesses();
        BigInteger[] shareholder = new BigInteger[currentViewProcesses.length];
        for (int i = 0; i < currentViewProcesses.length; i++) {
            shareholder[i] = BigInteger.valueOf(currentViewProcesses[i] + 1);
        }
        vss = new VSSFacade(p, generator, field, view.getF(), shareholder, dataEncryptionAlgorithm, dataEncryptionKeySize, shareEncryptionAlgorithm);
    }

    public VerifiableShare extractShare(PrivatePublishedShares privateShares) throws SecretSharingException {
        return vss.extractShare(privateShares, shareholder, decipheringKey);
    }
}
