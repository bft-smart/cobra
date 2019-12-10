package confidential.server;

import bftsmart.reconfiguration.views.View;
import confidential.CobraConfidentialityScheme;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.security.Key;

public class ServerConfidentialityScheme extends CobraConfidentialityScheme {
    private final Key decipheringKey;
    private final BigInteger me;

    public ServerConfidentialityScheme(int processId, View view) throws SecretSharingException {
        super(view);
        decipheringKey = keysManager.getDecryptionKeyFor(processId);
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
