package confidential.statemanagement.resharing;

import bftsmart.reconfiguration.ServerViewController;
import confidential.Configuration;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.privatestate.sender.BlindedShares;
import confidential.statemanagement.privatestate.sender.BlindedStateSender;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ResharingBlindedStateSender extends BlindedStateSender {

    public ResharingBlindedStateSender(ServerViewController svController, byte[] commonState, LinkedList<Share> shares,
                                       LinkedList<Commitment> commitments, int blindedStateReceiverPort,
                                       ServerConfidentialityScheme confidentialityScheme,
                                       boolean iAmStateSender, int... blindedStateReceivers) {
        super(svController, commonState, shares, commitments, blindedStateReceiverPort, confidentialityScheme, iAmStateSender,
                blindedStateReceivers);
    }

    @Override
    protected BlindedShares computeBlindedShares(LinkedList<Share> shares, LinkedList<Commitment> commitments,
                                                 VerifiableShare[] blindingShares) {
        logger.debug("Computing blinded shares");
        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        int nShares = shares.size();
        byte[][] resultingShares = new byte[nShares][];
        Commitment[] resultingCommitments = new Commitment[nShares];

        Iterator<Share> shareIterator = shares.iterator();
        Iterator<Commitment> commitmentsIterator = commitments.iterator();
        CountDownLatch latch = new CountDownLatch(nShares);
        BigInteger field = confidentialityScheme.getField();
        CommitmentScheme commitmentScheme = confidentialityScheme.getCommitmentScheme();
        for (int i = 0; i < nShares; i++) {
            VerifiableShare blindingShare = blindingShares[i];
            Share share = shareIterator.next();
            Commitment commitment = commitmentsIterator.next();
            int finalI = i;
            executorService.execute(() -> {
                try {
                    Commitment blindedCommitment = commitmentScheme.sumCommitments(commitment,
                            blindingShare.getCommitments());

                    BigInteger blindedShare = share.getShare().add(blindingShare.getShare().getShare()).mod(field);
                    resultingShares[finalI] = blindedShare.toByteArray();
                    resultingCommitments[finalI] = blindedCommitment;
                } catch (SecretSharingException e) {
                    logger.error("Failed to create blinded share", e);
                }
                latch.countDown();
            });
        }

        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        executorService.shutdown();

        return new BlindedShares(resultingShares, resultingCommitments);
    }
}
