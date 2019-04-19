package confidential.server;

import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.VerifiableShare;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import static confidential.Configuration.*;

public class ServerConfidentialityScheme {
    private final Key decipheringKey;
    private final BigInteger shareholder;
    private final VSSFacade vss;

    public ServerConfidentialityScheme(int processId, int currentViewF, int[] currentViewProcesses) throws SecretSharingException {
        decipheringKey = new SecretKeySpec(defaultKeys[processId].toByteArray(), shareEncryptionAlgorithm);
        shareholder = BigInteger.valueOf(processId + 1);
        BigInteger[] shareholder = new BigInteger[currentViewProcesses.length];
        for (int i = 0; i < currentViewProcesses.length; i++) {
            shareholder[i] = BigInteger.valueOf(currentViewProcesses[i] + 1);
        }
        vss = new VSSFacade(p, generator, field, currentViewF, shareholder, dataEncryptionAlgorithm, dataEncryptionKeySize, shareEncryptionAlgorithm);
    }

    public VerifiableShare extractShare(PrivatePublishedShares privateShares) throws SecretSharingException {
        return vss.extractShare(privateShares, shareholder, decipheringKey);
    }
}
