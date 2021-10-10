package confidential.statemanagement.recovery;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import confidential.Configuration;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.privatestate.sender.BlindedShares;
import confidential.statemanagement.privatestate.sender.BlindedStateSender;
import confidential.statemanagement.privatestate.sender.StateSeparationListener;
import vss.commitment.Commitment;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class RecoveryBlindedStateSender extends BlindedStateSender {

    public RecoveryBlindedStateSender(ServerViewController svController, DefaultApplicationState applicationState,
                                      int blindedStateReceiverPort, ServerConfidentialityScheme confidentialityScheme,
                                      boolean iAmStateSender, StateSeparationListener stateSeparationListener,
                                      int... blindedStateReceivers) {
        super(svController, applicationState, blindedStateReceiverPort, confidentialityScheme, iAmStateSender,
                stateSeparationListener, blindedStateReceivers);
    }

    @Override
    protected BlindedShares computeBlindedShares(LinkedList<Share> shares, LinkedList<Commitment> commitments,
                                                 VerifiableShare[] blindingShares) {
        logger.debug("Computing blinded shares");
        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        int nShares = shares.size();
        byte[][] resultingShares = new byte[nShares][];
        Commitment[] resultingCommitments = new Commitment[nShares * 2];

        Iterator<Share> shareIterator = shares.iterator();
        Iterator<Commitment> commitmentsIterator = commitments.iterator();
        CountDownLatch latch = new CountDownLatch(nShares);
        BigInteger field = confidentialityScheme.getField();
        int recoveringServer = blindedStateReceivers[0];
        for (int i = 0; i < nShares; i++) {
            VerifiableShare blindingShare = blindingShares[i];
            Share share = shareIterator.next();
            Commitment commitment = commitmentsIterator.next();
            int finalI = i;
            executorService.execute(() -> {
                int index = finalI * 2;
                BigInteger blindedShare = share.getShare().add(blindingShare.getShare().getShare()).mod(field);
                resultingShares[finalI] = confidentialityScheme.encryptDataFor(recoveringServer,
                        blindedShare.toByteArray());
                resultingCommitments[index] = commitment;
                resultingCommitments[index + 1] = blindingShare.getCommitments();
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
