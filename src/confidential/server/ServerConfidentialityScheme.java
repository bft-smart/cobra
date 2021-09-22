package confidential.server;

import bftsmart.reconfiguration.views.View;
import confidential.CobraConfidentialityScheme;
import confidential.encrypted.EncryptedPublishedShares;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;

public class ServerConfidentialityScheme extends CobraConfidentialityScheme {
    private final BigInteger me;
    private final int processId;

    public ServerConfidentialityScheme(int processId, View view) throws SecretSharingException {
        super(view);
        me = getShareholder(processId);
        this.processId = processId;
    }

    /**
     * Extract this shareholder's share and deciphers it.
     * @param privateShares Encrypted shares
     * @return Deciphered share
     * @throws SecretSharingException If encrypted shares do not contain this shareholder's share
     */
    public VerifiableShare extractShare(EncryptedPublishedShares privateShares) throws SecretSharingException {
        byte[] encryptedShare = privateShares.getShareOf(processId);
        if (encryptedShare == null)
            throw new SecretSharingException("Share not found");
        BigInteger decryptedShare = decryptShareFor(processId,
                encryptedShare);
        Share share = new Share(me, decryptedShare);
        Commitment commitment = getCommitmentScheme().extractCommitment(me, privateShares.getCommitment());
        return new VerifiableShare(share, commitment, privateShares.getSharedData());
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
