package confidential.server;

import bftsmart.reconfiguration.views.View;
import confidential.CobraConfidentialityScheme;
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

public class ServerConfidentialityScheme extends CobraConfidentialityScheme {
    private final Key decipheringKey;
    private final BigInteger me;

    public ServerConfidentialityScheme(int processId, View view) throws SecretSharingException {
        super(view);
        decipheringKey = new SecretKeySpec(defaultKeys[processId].toByteArray(), shareEncryptionAlgorithm);
        me = getShareholder(processId);
    }

    public VerifiableShare extractShare(PrivatePublishedShares privateShares) throws SecretSharingException {
        return vss.extractShare(privateShares, me, decipheringKey);
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

    public BigInteger getMyShareholderId() {
        return me;
    }
}
