package confidential.benchmark;

import confidential.Configuration;
import vss.Constants;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.polynomial.Polynomial;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

public class FullResharingBenchmark {
    private static final BigInteger keyNumber = new BigInteger("937810634060551071826485204471949219646466658841719067506");
    private static int oldThreshold;
    private static int oldN;
    private static int newN;
    private static SecureRandom rndGenerator;
    private static BigInteger[] oldShareholders;
    private static BigInteger[] newShareholders;
    private static Map<BigInteger, Key> keys;
    private static boolean verifyCorrectness;
    private static int nProcessingThreads;

    public static void main(String[] args) throws SecretSharingException, InterruptedException, ExecutionException {
        if (args.length != 7) {
            System.out.println("USAGE: ... confidential.benchmark.FullResharingBenchmark " +
                    "<threshold> <num secrets> <warm up iterations> <test iterations> " +
                    "<num processing threads> <verify correctness> <commitment scheme -> linear|constant>");
            System.exit(-1);
        }

        oldThreshold = Integer.parseInt(args[0]);
        int nSecrets = Integer.parseInt(args[1]);
        int warmUpIterations = Integer.parseInt(args[2]);
        int testIterations = Integer.parseInt(args[3]);
        nProcessingThreads = Integer.parseInt(args[4]);
        verifyCorrectness = Boolean.parseBoolean(args[5]);
        String commitmentSchemeName = args[6];

        int newThreshold = oldThreshold;
        oldN = oldThreshold + 2;
        newN = newThreshold + 2;

        System.out.println("old t = " + oldThreshold);
        System.out.println("old n = " + oldN);
        System.out.println("number of secrets = " + nSecrets);
        System.out.println("commitment scheme = " + commitmentSchemeName);
        System.out.println();

        oldShareholders = new BigInteger[oldN];
        keys = new HashMap<>(oldN + newN);
        for (int i = 0; i < oldN; i++) {
            BigInteger shareholder = BigInteger.valueOf(i + 1);
            oldShareholders[i] = shareholder;
            keys.put(shareholder, new SecretKeySpec(keyNumber.toByteArray(), "AES"));
        }

        newShareholders = new BigInteger[newN];
        for (int i = 0; i < newN; i++) {
            BigInteger shareholder = BigInteger.valueOf(i + 1);
            newShareholders[i] = shareholder;
            keys.put(shareholder, new SecretKeySpec(keyNumber.toByteArray(), "AES"));
        }

        Configuration configuration = Configuration.getInstance();

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(oldThreshold));
        properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, configuration.getDataEncryptionAlgorithm());
        properties.put(Constants.TAG_SHARE_ENCRYPTION_ALGORITHM, configuration.getShareEncryptionAlgorithm());
        properties.put(Constants.TAG_PRIME_FIELD, configuration.getPrimeField());
        properties.put(Constants.TAG_SUB_FIELD, configuration.getSubPrimeField());
        properties.put(Constants.TAG_GENERATOR, configuration.getGenerator());

        if (commitmentSchemeName.equals("linear")) {
            properties.put(Constants.TAG_COMMITMENT_SCHEME, Constants.VALUE_FELDMAN_SCHEME);
        } else if (commitmentSchemeName.equals("constant")) {
            properties.put(Constants.TAG_COMMITMENT_SCHEME, Constants.VALUE_KATE_SCHEME);
        } else
            throw new IllegalStateException("Commitment scheme is unknown");

        rndGenerator = new SecureRandom("ola".getBytes());
        VSSFacade vssFacade = new VSSFacade(properties, oldShareholders);

        System.out.println("Warming up (" + warmUpIterations + " iterations)");
        if (warmUpIterations > 0)
            runTests(warmUpIterations, false, nSecrets, vssFacade);
        System.out.println("Running test (" + testIterations + " iterations)");
        if (testIterations > 0)
            runTests(testIterations, true, nSecrets, vssFacade);
    }

    private static void runTests(int nTests, boolean printResults, int nSecrets,
                                 VSSFacade vssFacade) throws SecretSharingException, InterruptedException {
        BigInteger field = vssFacade.getField();
        CommitmentScheme commitmentScheme = vssFacade.getCommitmentScheme();
        BigInteger q = getRandomNumber(field.bitLength() - 1);

        byte[] secret = new byte[1024];
        rndGenerator.nextBytes(secret);
        PrivatePublishedShares privateShares = vssFacade.share(secret, keys);
        BigInteger[][] allQOldPoints = new BigInteger[nSecrets][oldShareholders.length];
        BigInteger[][] allQNewPoints = new BigInteger[nSecrets][newShareholders.length];
        Commitment[][] allQOldCommitments = new Commitment[nSecrets][oldShareholders.length];
        Commitment[][] allQNewCommitments = new Commitment[nSecrets][newShareholders.length];

        BigInteger[][][] qOldProposalPoints = new BigInteger[nSecrets][oldShareholders.length][];
        BigInteger[][][] qNewProposalPoints = new BigInteger[nSecrets][newShareholders.length][];
        Commitment[][] qOldProposalCommitments = new Commitment[nSecrets][oldShareholders.length];
        Commitment[][] qNewProposalCommitments = new Commitment[nSecrets][newShareholders.length];
        ExecutorService executor = Executors.newFixedThreadPool(nProcessingThreads);
        CountDownLatch preComputationLatch = new CountDownLatch(nSecrets);
        for (int j = 0; j < nSecrets; j++) {
            int finalJ = j;
            executor.execute(() -> {
                for (int i = 0; i < oldShareholders.length; i++) {
                    Polynomial qOld = new Polynomial(field, oldThreshold, q, rndGenerator);
                    Commitment qOldCommitment = commitmentScheme.generateCommitments(qOld, BigInteger.ZERO);
                    BigInteger[] qOldPoints = generateShares(oldShareholders, qOld);
                    qOldProposalPoints[finalJ][i] = qOldPoints;
                    qOldProposalCommitments[finalJ][i] = qOldCommitment;
                }
                for (int i = 0; i < newShareholders.length; i++) {
                    Polynomial qNew = new Polynomial(field, oldThreshold, q, rndGenerator);
                    Commitment qNewCommitment = commitmentScheme.generateCommitments(qNew, BigInteger.ZERO);
                    BigInteger[] qNewPoints = generateShares(newShareholders, qNew);
                    qNewProposalPoints[finalJ][i] = qNewPoints;
                    qNewProposalCommitments[finalJ][i] = qNewCommitment;
                }
                preComputationLatch.countDown();
            });
        }

        preComputationLatch.await();

        for (int i = 0; i < nSecrets; i++) {
            for (int j = 1; j < oldShareholders.length; j++) {
                BigInteger temp = BigInteger.ZERO;
                for (int k = 0; k <= oldThreshold; k++) {
                    temp = temp.add(qOldProposalPoints[i][k][j]).mod(field);
                }
                allQOldPoints[i][j] = temp;
            }

            for (int j = 1; j < newShareholders.length; j++) {
                BigInteger temp = BigInteger.ZERO;
                for (int k = 0; k <= oldThreshold; k++) {
                    temp = temp.add(qNewProposalPoints[i][k][j]).mod(field);
                }
                allQNewPoints[i][j] = temp;
            }
        }

        Set<BigInteger> corruptedShareholders = new HashSet<>(oldN);

        long start, end;
        long[] sharingTimes = new long[nTests];
        long[] shareBlindingTimes = new long[nTests];
        long[] secretBlindingTimes = new long[nTests];
        long[] commitmentRecoveryTimes = new long[nTests];
        long[] commitmentRefreshTimes = new long[nTests];
        long[] sequentialProposalSharesCreationTimes = new long[nTests];
        long[] sequentialProposalCommitmentCreationTimes = new long[nTests];
        long[] proposalCreationTimes = new long[nTests];
        long[] proposalSelectionTimes = new long[nTests];
        long[] finalPointComputationTimes = new long[nTests];
        long[] finalCommitmentsComputationTimes = new long[nTests];
        long[] refreshTimes = new long[nTests];
        long[] allTimes = new long[nTests];

        for (int nT = 0; nT < nTests; nT++) {
            corruptedShareholders.clear();
            long sharingTime = 0;
            long shareBlindingTime = 0;
            long secretBlindingTime = 0;
            long commitmentRecoveryTime = 0;
            long commitmentRefreshTime = 0;
            AtomicLong sequentialProposalSharesCreationTime = new AtomicLong(0);
            AtomicLong sequentialProposalCommitmentCreationTime = new AtomicLong(0);
            long proposalCreationTime = 0;
            long proposalSelectionTime = 0;
            long finalPointComputationTime = 0;
            long finalCommitmentsComputationTime = 0;
            long refreshTime = 0;
            long allTimeStart, allTimeEnd;
            allTimeStart = System.nanoTime();

            //Creating renewal polynomials
            //Proposal creation
            CountDownLatch renewalPolynomialsLatch = new CountDownLatch(nSecrets);
            start = System.nanoTime();
            for (int i = 0; i < nSecrets; i++) {
                executor.execute(() -> {
                    long tempStart, tempEnd;
                    tempStart = System.nanoTime();
                    Polynomial qOld = new Polynomial(field, oldThreshold, q, rndGenerator);
                    Polynomial qNew = new Polynomial(field, oldThreshold, q, rndGenerator);
                    generateShares(oldShareholders, qOld);
                    generateShares(newShareholders, qNew);
                    tempEnd = System.nanoTime();
                    sequentialProposalSharesCreationTime.addAndGet(tempEnd - tempStart);

                    tempStart = System.nanoTime();
                    commitmentScheme.generateCommitments(qOld);
                    commitmentScheme.generateCommitments(qNew);
                    tempEnd = System.nanoTime();
                    sequentialProposalCommitmentCreationTime.addAndGet(tempEnd - tempStart);

                    renewalPolynomialsLatch.countDown();
                });
            }
            renewalPolynomialsLatch.await();
            end = System.nanoTime();
            proposalCreationTime += end - start;

            //Proposal selection/verification
            start = System.nanoTime();
            CountDownLatch verificationLatch = new CountDownLatch(nSecrets);
            for (int i = 0; i < nSecrets; i++) {
                int finalI = i;
                executor.execute(() -> {
                    for (int j = 0; j <= oldThreshold; j++) {
                        Share oldShare = new Share(oldShareholders[0], qOldProposalPoints[finalI][j][0]);
                        Share newShare = new Share(newShareholders[0], qNewProposalPoints[finalI][j][0]);
                        Commitment oldCommitment = qOldProposalCommitments[finalI][j];
                        Commitment newCommitment = qNewProposalCommitments[finalI][j];
                        if (!commitmentScheme.checkValidityWithoutPreComputation(oldShare, oldCommitment)
                                || !commitmentScheme.checkValidityWithoutPreComputation(newShare, newCommitment)
                                || !commitmentScheme.checkValidityOfPolynomialsProperty(BigInteger.ZERO,
                                oldCommitment, newCommitment))
                            throw new IllegalStateException("Invalid point");
                    }
                    verificationLatch.countDown();
                });
            }
            verificationLatch.await();
            end = System.nanoTime();
            proposalSelectionTime += end - start;

            //Computing final point
            for (int i = 0; i < nSecrets; i++) {
                start = System.nanoTime();
                BigInteger temp = BigInteger.ZERO;
                BigInteger temp2 = BigInteger.ZERO;
                for (int k = 0; k <= oldThreshold; k++) {
                    temp = temp.add(qOldProposalPoints[i][k][0]).mod(field);
                    temp2 = temp2.add(qNewProposalPoints[i][k][0]).mod(field);
                }
                allQOldPoints[i][0] = temp;
                allQNewPoints[i][0] = temp2;
                end = System.nanoTime();
                finalPointComputationTime += end - start;

                start = System.nanoTime();
                Commitment[] oldCommitments = new Commitment[oldThreshold + 1];
                Commitment[] newCommitments = new Commitment[oldThreshold + 1];
                for (int k = 0; k <= oldThreshold; k++) {
                    oldCommitments[k] = qOldProposalCommitments[i][k];
                    newCommitments[k] = qNewProposalCommitments[i][k];
                }
                Commitment oldCommitment = commitmentScheme.sumCommitments(oldCommitments);
                Commitment newCommitment = commitmentScheme.sumCommitments(newCommitments);
                allQOldCommitments[i][0] = commitmentScheme.extractCommitment(oldShareholders[0], oldCommitment);
                allQNewCommitments[i][0] = commitmentScheme.extractCommitment(newShareholders[0], newCommitment);
                end = System.nanoTime();
                finalCommitmentsComputationTime += end - start;

                for (int j = 1; j < oldShareholders.length; j++) {
                    allQOldCommitments[i][j] = commitmentScheme.extractCommitment(oldShareholders[j], oldCommitment);
                }
                for (int j = 1; j < newShareholders.length; j++) {
                    allQNewCommitments[i][j] = commitmentScheme.extractCommitment(newShareholders[j], newCommitment);
                }
            }

            //Extracting shares
            VerifiableShare[][] allVerifiableShares = new VerifiableShare[nSecrets][];
            for (int nS = 0; nS < nSecrets; nS++) {
                VerifiableShare[] verifiableShares = new VerifiableShare[oldN];
                start = System.nanoTime();
                verifiableShares[0] = vssFacade.extractShare(privateShares, oldShareholders[0],
                        keys.get(oldShareholders[0]));
                end = System.nanoTime();
                sharingTime += end - start;
                for (int i = 1; i < oldN; i++) {
                    verifiableShares[i] = vssFacade.extractShare(privateShares, oldShareholders[i],
                            keys.get(oldShareholders[i]));
                }
                allVerifiableShares[nS] = verifiableShares;
            }
            byte[] sharedData = allVerifiableShares[0][0].getSharedData();

            //Creating blinded shares
            for (int nS = 0; nS < nSecrets; nS++) {
                VerifiableShare[] verifiableShares = allVerifiableShares[nS];
                BigInteger[] qOldPoints = allQOldPoints[nS];
                start = System.nanoTime();
                verifiableShares[0].getShare()
                        .setShare(qOldPoints[0].add(verifiableShares[0].getShare().getShare()).mod(field));
                end = System.nanoTime();
                shareBlindingTime += end - start;

                for (int i = 1; i < oldN; i++) {
                    verifiableShares[i].getShare()
                            .setShare(qOldPoints[i].add(verifiableShares[i].getShare().getShare()).mod(field));
                }
            }

            //Creating blinded secret
            BigInteger[] allBlindedSecrets = new BigInteger[nSecrets];
            Share[][] allBlindedShares = new Share[nSecrets][];
            CountDownLatch blindedSecretCounter = new CountDownLatch(nSecrets);
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                VerifiableShare[] verifiableShares = allVerifiableShares[nS];
                int finalNS = nS;
                executor.execute(() -> {
                    try {
                        BigInteger blindedSecret = null;
                        Share[] blindedShares =
                                new Share[oldThreshold + (corruptedShareholders.size() < oldThreshold ? 2 : 1)];
                        int j = 0;
                        for (VerifiableShare vs : verifiableShares) {
                            Share share = vs.getShare();
                            if (corruptedShareholders.contains(share.getShareholder())) {
                                continue;
                            }
                            blindedShares[j++] = share;
                            if (j == blindedShares.length) {
                                break;
                            }
                        }
                        Polynomial polynomial = new Polynomial(field, blindedShares);

                        if (polynomial.getDegree() != oldThreshold) {
                            System.err.println("Invalid blinded secret");
                            System.exit(-1);
                        } else {
                            blindedSecret = polynomial.evaluateAt(BigInteger.ZERO);
                        }
                        allBlindedSecrets[finalNS] = blindedSecret;
                        allBlindedShares[finalNS] = blindedShares;
                        blindedSecretCounter.countDown();
                    } catch (SecretSharingException e) {
                        e.printStackTrace();
                    }
                });
            }

            blindedSecretCounter.await();
            end = System.nanoTime();
            secretBlindingTime += end - start;

            //Processing commitments
            Commitment[] allBlindedSecretCommitment = new Commitment[nSecrets];
            CountDownLatch blindedSecretCommitmentCounter = new CountDownLatch(nSecrets);
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                int finalNS = nS;
                VerifiableShare[] verifiableShares = allVerifiableShares[nS];
                Share[] blindedShares = allBlindedShares[nS];
                Commitment[] tempQOldCommitment = allQOldCommitments[nS];
                executor.execute(() -> {
                    try {
                        Map<BigInteger, Commitment> allCurrentCommitments = new HashMap<>(oldN);
                        for (VerifiableShare verifiableShare : verifiableShares) {
                            allCurrentCommitments.put(verifiableShare.getShare().getShareholder(),
                                    verifiableShare.getCommitments());
                        }
                        Map<BigInteger, Commitment> allTempQOldCommitment = new HashMap<>(oldN);
                        for (int i = 0; i < tempQOldCommitment.length; i++) {
                            allTempQOldCommitment.put(oldShareholders[i], tempQOldCommitment[i]);
                        }
                        Commitment qOldCommitment = commitmentScheme.combineCommitments(allTempQOldCommitment);
                        Commitment combinedCommitment = commitmentScheme.combineCommitments(allCurrentCommitments);
                        Commitment verificationCommitment = commitmentScheme.sumCommitments(qOldCommitment, combinedCommitment);
                        int minNumberOfCommitments = corruptedShareholders.size() >= oldThreshold ? oldThreshold : oldThreshold + 1;
                        Map<BigInteger, Commitment> validCommitments = new HashMap<>(minNumberOfCommitments);
                        for (Share blindingShare : blindedShares) {
                            validCommitments.put(blindingShare.getShareholder(),
                                    commitmentScheme.extractCommitment(blindingShare.getShareholder(), verificationCommitment));
                            if (validCommitments.size() == minNumberOfCommitments) {
                                break;
                            }
                        }
                        Commitment blindedSecretCommitment;
                        try {
                            blindedSecretCommitment = commitmentScheme.recoverCommitment(BigInteger.ZERO, validCommitments);
                        } catch (SecretSharingException e) {
                            System.err.println("Invalid Commitments");
                            System.exit(-1);
                            validCommitments.clear();
                            blindedSecretCommitment = null;
                        }
                        allBlindedSecretCommitment[finalNS] = blindedSecretCommitment;
                        blindedSecretCommitmentCounter.countDown();
                    } catch (SecretSharingException e) {
                        e.printStackTrace();
                    }
                });
            }
            blindedSecretCommitmentCounter.await();
            end = System.nanoTime();
            commitmentRecoveryTime += end - start;

            Commitment[] allRefreshedShareCommitment = new Commitment[nSecrets];
            CountDownLatch refreshCommitmentCounter = new CountDownLatch(nSecrets);
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                int finalNS = nS;
                Commitment blindedSecretCommitment = allBlindedSecretCommitment[nS];
                Commitment qNewCommitment = allQNewCommitments[nS][0];
                executor.execute(() -> {
                    try {
                        Commitment refreshedShareCommitment = commitmentScheme.subtractCommitments(blindedSecretCommitment,
                                qNewCommitment);
                        allRefreshedShareCommitment[finalNS] = refreshedShareCommitment;
                        refreshCommitmentCounter.countDown();
                    } catch (SecretSharingException e) {
                        e.printStackTrace();
                    }

                });
            }
            refreshCommitmentCounter.await();
            end = System.nanoTime();
            commitmentRefreshTime += end - start;

            //Renewing shares
            VerifiableShare[][] allRenewedShares = new VerifiableShare[nSecrets][];
            for (int nS = 0; nS < nSecrets; nS++) {
                Commitment refreshedShareCommitment = allRefreshedShareCommitment[nS];
                BigInteger blindedSecret = allBlindedSecrets[nS];
                VerifiableShare[] renewedShares = new VerifiableShare[newN];
                BigInteger[] qNewPoints = allQNewPoints[nS];
                start = System.nanoTime();
                BigInteger refreshedShare = blindedSecret.subtract(qNewPoints[0]).mod(field);
                renewedShares[0] = new VerifiableShare(
                        new Share(newShareholders[0], refreshedShare),
                        refreshedShareCommitment,
                        sharedData
                );
                end = System.nanoTime();
                refreshTime += end - start;

                if (verifyCorrectness) {
                    Commitment blindedSecretCommitment = allBlindedSecretCommitment[nS];
                    for (int i = 1; i < newN; i++) {
                        Commitment qNewCommitment = allQNewCommitments[nS][i];
                        refreshedShare = blindedSecret.subtract(qNewPoints[i]).mod(field);
                        refreshedShareCommitment = commitmentScheme.subtractCommitments(blindedSecretCommitment,
                                qNewCommitment);
                        renewedShares[i] = new VerifiableShare(
                                new Share(newShareholders[i], refreshedShare),
                                refreshedShareCommitment,
                                sharedData
                        );
                    }
                }
                allRenewedShares[nS] = renewedShares;
            }

            //Checking correctness of renewed shares
            if (verifyCorrectness) {
                for (int nS = 0; nS < nSecrets; nS++) {
                    VerifiableShare[] renewedShares = allRenewedShares[nS];
                    Share[] shares = new Share[newN];
                    Map<BigInteger, Commitment> commitments = new HashMap<>(newN);
                    for (int i = 0; i < newN; i++) {
                        VerifiableShare vs = renewedShares[i];
                        shares[i] = vs.getShare();
                        commitments.put(vs.getShare().getShareholder(), vs.getCommitments());
                    }
                    Commitment commitment = commitmentScheme.combineCommitments(commitments);
                    OpenPublishedShares openShares = new OpenPublishedShares(shares,
                            commitment, sharedData);
                    byte[] recoveredSecret = vssFacade.combine(openShares);
                    if (!Arrays.equals(secret, recoveredSecret))
                        throw new IllegalStateException("Secret is different");
                }
            }
            allTimeEnd = System.nanoTime();

            sharingTimes[nT] = sharingTime;
            shareBlindingTimes[nT] = shareBlindingTime;
            secretBlindingTimes[nT] = secretBlindingTime;
            commitmentRecoveryTimes[nT] = commitmentRecoveryTime;
            commitmentRefreshTimes[nT] = commitmentRefreshTime;
            sequentialProposalSharesCreationTimes[nT] = sequentialProposalSharesCreationTime.get();
            sequentialProposalCommitmentCreationTimes[nT] = sequentialProposalCommitmentCreationTime.get();
            proposalCreationTimes[nT] = proposalCreationTime;
            proposalSelectionTimes[nT] = proposalSelectionTime;
            finalPointComputationTimes[nT] = finalPointComputationTime;
            finalCommitmentsComputationTimes[nT] = finalCommitmentsComputationTime;
            refreshTimes[nT] = refreshTime;
            allTimes[nT] = allTimeEnd - allTimeStart;
        }

        executor.shutdown();
        if (printResults) {
            double sequentialProposalShareCreationAvg = computeAverage(sequentialProposalSharesCreationTimes);
            double sequentialProposalCommitmentsCreationAvg = computeAverage(sequentialProposalCommitmentCreationTimes);
            double proposalCreationAvg = computeAverage(proposalCreationTimes);
            double proposalSelectionAvg = computeAverage(proposalSelectionTimes);
            double finalPointComputationAvg = computeAverage(finalPointComputationTimes);
            double finalCommitmentsComputationAvg = computeAverage(finalCommitmentsComputationTimes);

            double sharingAvg = computeAverage(sharingTimes);
            double shareBlindingAvg = computeAverage(shareBlindingTimes);
            double secretBlindingAvg = computeAverage(secretBlindingTimes);
            double commitmentRecoveryAvg = computeAverage(commitmentRecoveryTimes);
            double commitmentRefreshAvg = computeAverage(commitmentRefreshTimes);
            double refreshTimeAvg = computeAverage(refreshTimes);
            double allTimeAvg = computeAverage(allTimes);

            double totalResharingPolynomialsCreation = proposalCreationAvg + proposalSelectionAvg
                    + finalPointComputationAvg + finalCommitmentsComputationAvg;
            double resharingTotal = shareBlindingAvg + secretBlindingAvg + commitmentRecoveryAvg
                    + commitmentRefreshAvg + refreshTimeAvg;
            double resharingWithPolynomial = totalResharingPolynomialsCreation + resharingTotal;

            System.out.println();
            System.out.println("Sequential proposal shares creation: " + sequentialProposalShareCreationAvg + " ms");
            System.out.println("Sequential proposal commitments creation: " + sequentialProposalCommitmentsCreationAvg + " ms");
            System.out.println("Proposal creation: " + proposalCreationAvg + " ms");
            System.out.println("Proposal selection: " + proposalSelectionAvg + " ms");
            System.out.println("Final point computation: " + finalPointComputationAvg + " ms");
            System.out.println("Final commitments computation: " + finalCommitmentsComputationAvg + " ms");
            System.out.println("Total resharing polynomials creation: " + totalResharingPolynomialsCreation + " ms");
            System.out.println();
            System.out.println("Share extraction: " + sharingAvg + " ms");
            System.out.println("Share blinding: " + shareBlindingAvg + " ms");
            System.out.println("Blinded secret: " + secretBlindingAvg + " ms");
            System.out.println("Commitment recovery: " + commitmentRecoveryAvg + " ms");
            System.out.println("Commitment refresh: " + commitmentRefreshAvg + " ms");
            System.out.println("Refresh: " + refreshTimeAvg + " ms");
            System.out.println("Total: " + resharingTotal + " ms");
            System.out.println();
            System.out.println("Polynomial + Resharing: " + resharingWithPolynomial);
            System.out.println("All: " + allTimeAvg + " ms");
        }
    }

    private static double computeAverage(long[] values) {
        return ((double) Arrays.stream(values).sum() / values.length) / 1_000_000.0;
    }

    private static BigInteger[] generateShares(BigInteger[] shareholders, Polynomial polynomial) {
        BigInteger[] result = new BigInteger[shareholders.length];
        for (int i = 0; i < shareholders.length; i++) {
            result[i] = polynomial.evaluateAt(shareholders[i]);
        }
        return result;
    }

    private static BigInteger getRandomNumber(int numBits) {
        BigInteger rndBig = new BigInteger(numBits, rndGenerator);
        if (rndBig.compareTo(BigInteger.ZERO) == 0)
            rndBig = rndBig.add(BigInteger.ONE);
        return rndBig;
    }
}
