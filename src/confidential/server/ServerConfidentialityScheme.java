package confidential.server;

import bftsmart.reconfiguration.views.View;
import vss.Constants;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.interpolation.InterpolationStrategy;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.VerifiableShare;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.util.Properties;

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

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(view.getF()));
        properties.put(Constants.TAG_PRIME_FIELD, str_p);
        properties.put(Constants.TAG_SUB_FIELD, str_field);
        properties.put(Constants.TAG_GENERATOR, str_generator);
        properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, dataEncryptionAlgorithm);
        properties.put(Constants.TAG_SHARE_ENCRYPTION_ALGORITHM, shareEncryptionAlgorithm);
        properties.put(Constants.TAG_COMMITMENT_SCHEME, Constants.VALUE_KATE_SCHEME);

        vss = new VSSFacade(properties, shareholder);
    }

    public VerifiableShare extractShare(PrivatePublishedShares privateShares) throws SecretSharingException {
        return vss.extractShare(privateShares, shareholder, decipheringKey);
    }

    public CommitmentScheme getCommitmentScheme() {
        return vss.getCommitmentScheme();
    }

    public InterpolationStrategy getInterpolationStrategy() {
        return vss.getInterpolationStrategy();
    }

    public BigInteger getField() {
        return vss.getField();
    }
}
