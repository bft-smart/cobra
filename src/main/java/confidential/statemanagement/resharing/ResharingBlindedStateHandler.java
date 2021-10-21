package confidential.statemanagement.resharing;

import bftsmart.reconfiguration.ServerViewController;
import confidential.Configuration;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.ReconstructionCompleted;
import confidential.statemanagement.privatestate.receiver.BlindedStateHandler;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ResharingBlindedStateHandler extends BlindedStateHandler {
    private final int newF;
    private VerifiableShare[] refreshShares;
    private final Lock lock;
    private final Condition waitingForRefreshShares;

    public ResharingBlindedStateHandler(ServerViewController svController, int serverPort, int f, int newF, int quorum,
                                        int stateSenderReplica, ServerConfidentialityScheme confidentialityScheme,
                                        ReconstructionCompleted reconstructionListener) {
        super(svController, serverPort, f, quorum, stateSenderReplica, confidentialityScheme,
                reconstructionListener);
        this.newF = newF;
        this.lock = new ReentrantLock(true);
        this.waitingForRefreshShares = lock.newCondition();
    }

    public void setRefreshShares(VerifiableShare[] refreshShares) {
        lock.lock();
        this.refreshShares = refreshShares;
        waitingForRefreshShares.signal();
        lock.unlock();
    }

    @Override
    protected Share[] reconstructBlindedShares(int from, byte[][] shares) {
        BigInteger shareholder = confidentialityScheme.getShareholder(from);
        Share[] result = new Share[shares.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = new Share(shareholder, new BigInteger(shares[i]));
        }
        return result;
    }

    @Override
    protected Iterator<VerifiableShare> reconstructShares(int nShares,
                                                          Map<Integer, Share[]> allBlindedShares,
                                                          Map<BigInteger, Commitment[]> allBlindedCommitments) {
        lock.lock();
        if (refreshShares == null) {
            try {
                waitingForRefreshShares.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        lock.unlock();
        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        CountDownLatch latch = new CountDownLatch(nShares);

        VerifiableShare[] recoveredShares = new VerifiableShare[nShares];
        Integer[] servers = new Integer[allBlindedShares.size()];
        BigInteger[] shareholders = new BigInteger[allBlindedCommitments.size()];
        int k = 0;
        for (Integer server : allBlindedShares.keySet()) {
            servers[k++] = server;
        }

        k = 0;
        for (BigInteger shareholder : allBlindedCommitments.keySet()) {
            shareholders[k++] = shareholder;
        }

        for (int i = 0; i < nShares; i++) {
            Map<Integer, Share> blindedShares = new HashMap<>(stillValidSenders.size());
            Map<BigInteger, Commitment> blindedCommitments = new HashMap<>(stillValidSenders.size());
            for (Integer server : servers) {
                blindedShares.put(server, allBlindedShares.get(server)[i]);
            }
            for (BigInteger shareholder : shareholders) {
                blindedCommitments.put(shareholder, allBlindedCommitments.get(shareholder)[i]);
            }
            VerifiableShare refreshShare = refreshShares[i];
            int finalI = i;
            executorService.execute(() -> {
                try {
                    VerifiableShare vs = recoverShare(blindedShares, blindedCommitments);
                    if (vs == null) {
                        return;
                    }
                    BigInteger blindedSecret = vs.getShare().getShare();
                    BigInteger[] zeroConstants = new BigInteger[newF];
                    Arrays.fill(zeroConstants, BigInteger.ZERO);
                    Polynomial tempSecretPolynomial = new Polynomial(field, blindedSecret, zeroConstants);
                    Commitment blindedSecretCommitment = commitmentScheme.generateCommitments(tempSecretPolynomial);
                    BigInteger refreshedShare = blindedSecret.subtract(refreshShare.getShare().getShare()).mod(field);
                    Commitment refreshedShareCommitment = commitmentScheme.subtractCommitments(blindedSecretCommitment,
                            refreshShare.getCommitments());

                    vs.setCommitments(refreshedShareCommitment);
                    vs.getShare().setShare(refreshedShare);
                    vs.getShare().setShareholder(shareholderId);
                    recoveredShares[finalI] = vs;
                } catch (SecretSharingException e) {
                    logger.error("Failed to refresh a share", e);
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
        LinkedList<VerifiableShare> result = new LinkedList<>();
        for (VerifiableShare refreshedShare : recoveredShares) {
            if (refreshedShare == null)
                return null;
            result.add(refreshedShare);
        }
        return result.iterator();
    }

    private VerifiableShare recoverShare(Map<Integer, Share> blindedShares,
                                         Map<BigInteger, Commitment> blindedCommitments) {
        try {
            int corruptedServers = this.corruptedServers.get();
            Share[] recoveringShares = new Share[f + (corruptedServers < f ? 2 : 1)];
            int j = 0;
            for (Map.Entry<Integer, Share> entry : blindedShares.entrySet()) {
                Share share = entry.getValue();
                if (j < recoveringShares.length) {
                    recoveringShares[j++] = share;
                }
            }

            Polynomial polynomial = new Polynomial(field, recoveringShares);

            BigInteger blindedSecretNumber;
            Map<BigInteger, Commitment> validCommitments;
            Commitment verificationCommitments = commitmentScheme.combineCommitments(blindedCommitments);

            if (polynomial.getDegree() != f) {
                logger.warn("Using commitments to check shares");
                recoveringShares = new Share[f + 1];
                validCommitments = new HashMap<>(f);
                j = 0;
                Set<Integer> invalidSenders = new HashSet<>(f);
                for (Map.Entry<Integer, Share> entry : blindedShares.entrySet()) {
                    int server = entry.getKey();
                    BigInteger shareholder = confidentialityScheme.getShareholder(server);
                    if (commitmentScheme.checkValidityWithoutPreComputation(entry.getValue(), verificationCommitments)) {
                        recoveringShares[j++] = entry.getValue();
                        if (validCommitments.size() <= f) {
                            validCommitments.put(shareholder, blindedCommitments.get(shareholder));
                        }
                    } else {
                        logger.error("Server {} sent me invalid share", server);
                        blindedCommitments.remove(shareholder);
                        this.corruptedServers.incrementAndGet();
                        invalidSenders.add(server);
                        stillValidSenders.remove(server);
                    }
                }
                for (Integer server : invalidSenders) {
                    blindedShares.remove(server);
                }

                blindedSecretNumber = interpolationStrategy.interpolateAt(BigInteger.ZERO, recoveringShares);
            } else {
                blindedSecretNumber = polynomial.evaluateAt(BigInteger.ZERO);
                int minNumberOfCommitments = corruptedServers >= f ? f : f + 1;
                validCommitments = new HashMap<>(minNumberOfCommitments);

                for (Share recoveringShare : recoveringShares) {
                    validCommitments.put(recoveringShare.getShareholder(),
                            blindedCommitments.get(recoveringShare.getShareholder()));
                    if (validCommitments.size() == minNumberOfCommitments)
                        break;
                }
            }

            Commitment commitment;
            try {
                commitment = commitmentScheme.recoverCommitment(BigInteger.ZERO, validCommitments);
            } catch (SecretSharingException e) { //there is/are invalid witness(es)
                validCommitments.clear();
                for (Map.Entry<Integer, Share> entry : blindedShares.entrySet()) {
                    int server = entry.getKey();
                    BigInteger shareholder = confidentialityScheme.getShareholder(server);
                    if (commitmentScheme.checkValidityWithoutPreComputation(entry.getValue(), verificationCommitments)) {
                        validCommitments.put(shareholder, blindedCommitments.get(shareholder));
                        if (validCommitments.size() == f) {
                            break;
                        }
                    } else {
                        logger.error("Server {} send me an invalid commitment", server);
                        stillValidSenders.remove(server);
                        this.corruptedServers.incrementAndGet();
                    }
                }
                commitment = commitmentScheme.recoverCommitment(BigInteger.ZERO, validCommitments);
            }
            Share share = new Share(BigInteger.ZERO, blindedSecretNumber);
            return new VerifiableShare(share, commitment, null);
        } catch (SecretSharingException e) {
            logger.error("Failed to a recover share", e);
            return null;
        }
    }
}
