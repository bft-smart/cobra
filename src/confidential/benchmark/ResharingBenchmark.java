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
import java.util.concurrent.*;

public class ResharingBenchmark {
    private static final BigInteger keyNumber = new BigInteger("937810634060551071826485204471949219646466658841719067506");
    private static int oldThreshold;
    private static int newThreshold;
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
            System.out.println("USAGE: ... confidential.benchmark.ResharingBenchmark " +
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

        newThreshold = oldThreshold;
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
                                 VSSFacade vssFacade) throws SecretSharingException, InterruptedException, ExecutionException {
        BigInteger field = vssFacade.getField();
        CommitmentScheme commitmentScheme = vssFacade.getCommitmentScheme();
        BigInteger q = getRandomNumber(field.bitLength() - 1);

        Polynomial qOld = new Polynomial(field, oldThreshold, q, rndGenerator);
        Polynomial qNew = new Polynomial(field, oldThreshold, q, rndGenerator);

        Commitment qOldCommitment = commitmentScheme.generateCommitments(qOld);
        Commitment qNewCommitment = commitmentScheme.generateCommitments(qNew);

        BigInteger[] qOldPoints = generateShares(oldShareholders, qOld);
        BigInteger[] qNewPoints = generateShares(newShareholders, qNew);

        byte[] secret = new byte[1024];
        rndGenerator.nextBytes(secret);
        PrivatePublishedShares privateShares = vssFacade.share(secret, keys);

        Set<BigInteger> corruptedShareholders = new HashSet<>(oldN);

        long start, end;
        long[] sharingTimes = new long[nTests];
        long[] shareBlindingTimes = new long[nTests];
        long[] secretBlindingTimes = new long[nTests];
        long[] commitmentRecoveryTimes = new long[nTests];
        long[] commitmentRefreshTimes = new long[nTests];
        long[] refreshTimes = new long[nTests];
        long[] allTimes = new long[nTests];

        for (int nT = 0; nT < nTests; nT++) {
            corruptedShareholders.clear();
            long sharingTime = 0;
            long shareBlindingTime = 0;
            long secretBlindingTime = 0;
            long commitmentRecoveryTime = 0;
            long commitmentRefreshTime = 0;
            long refreshTime = 0;
            long allTimeStart, allTimeEnd;
            allTimeStart = System.nanoTime();

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
            ExecutorService executor = Executors.newFixedThreadPool(nProcessingThreads);
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
            executor.shutdown();;
            blindedSecretCounter.await();
            end = System.nanoTime();
            secretBlindingTime += end - start;

            //Processing commitments
            executor = Executors.newFixedThreadPool(nProcessingThreads);
            Commitment[] allBlindedSecretCommitment = new Commitment[nSecrets];
            CountDownLatch blindedSecretCommitmentCounter = new CountDownLatch(nSecrets);
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                int finalNS = nS;
                VerifiableShare[] verifiableShares = allVerifiableShares[nS];
                Share[] blindedShares = allBlindedShares[nS];
                executor.execute(() -> {
                    try {
                        Map<BigInteger, Commitment> allCurrentCommitments = new HashMap<>(oldN);
                        for (VerifiableShare verifiableShare : verifiableShares) {
                            allCurrentCommitments.put(verifiableShare.getShare().getShareholder(),
                                    verifiableShare.getCommitments());
                        }
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
            executor.shutdown();
            blindedSecretCommitmentCounter.await();
            end = System.nanoTime();
            commitmentRecoveryTime += end - start;

            executor = Executors.newFixedThreadPool(nProcessingThreads);
            Commitment[] allRefreshedShareCommitment = new Commitment[nSecrets];
            CountDownLatch refreshCommitmentCounter = new CountDownLatch(nSecrets);
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                int finalNS = nS;
                Commitment blindedSecretCommitment = allBlindedSecretCommitment[nS];
                executor.execute(() -> {
                    try {
                        Commitment refreshedShareCommitment = commitmentScheme.subtractCommitments(blindedSecretCommitment,
                                commitmentScheme.extractCommitment(newShareholders[0], qNewCommitment));
                        allRefreshedShareCommitment[finalNS] = refreshedShareCommitment;
                        refreshCommitmentCounter.countDown();
                    } catch (SecretSharingException e) {
                        e.printStackTrace();
                    }

                });
            }
            executor.shutdown();
            refreshCommitmentCounter.await();
            end = System.nanoTime();
            commitmentRefreshTime += end - start;

            //Renewing shares
            VerifiableShare[][] allRenewedShares = new VerifiableShare[nSecrets][];
            for (int nS = 0; nS < nSecrets; nS++) {
                Commitment refreshedShareCommitment = allRefreshedShareCommitment[nS];
                BigInteger blindedSecret = allBlindedSecrets[nS];
                VerifiableShare[] renewedShares = new VerifiableShare[newN];

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
                        refreshedShare = blindedSecret.subtract(qNewPoints[i]).mod(field);
                        refreshedShareCommitment = commitmentScheme.subtractCommitments(blindedSecretCommitment,
                                commitmentScheme.extractCommitment(newShareholders[i], qNewCommitment));
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
            refreshTimes[nT] = refreshTime;
            allTimes[nT] = allTimeEnd - allTimeStart;
        }

        if (printResults) {
            double sharingAvg = computeAverage(sharingTimes) / 1_000_000.0;
            double shareBlindingAvg = computeAverage(shareBlindingTimes) / 1_000_000.0;
            double secretBlindingAvg = computeAverage(secretBlindingTimes) / 1_000_000.0;
            double commitmentRecoveryAvg = computeAverage(commitmentRecoveryTimes) / 1_000_000.0;
            double commitmentRefreshAvg = computeAverage(commitmentRefreshTimes) / 1_000_000.0;
            double refreshTimeAvg = computeAverage(refreshTimes) / 1_000_000.0;
            double allTimeAvg = computeAverage(allTimes) / 1_000_000.0;

            System.out.println("Share extraction: " + sharingAvg + " ms");
            System.out.println("Share blinding: " + shareBlindingAvg + " ms");
            System.out.println("Blinded secret: " + secretBlindingAvg + " ms");
            System.out.println("Commitment recovery: " + commitmentRecoveryAvg + " ms");
            System.out.println("Commitment refresh: " + commitmentRefreshAvg + " ms");
            System.out.println("Refresh: " + refreshTimeAvg + " ms");
            System.out.println("Total: " + (shareBlindingAvg + secretBlindingAvg + commitmentRecoveryAvg
                    + commitmentRefreshAvg + refreshTimeAvg) + " ms");
            System.out.println("All: " + allTimeAvg + " ms");
        }
    }

    private static double computeAverage(long[] values) {
        return (double) Arrays.stream(values).sum() / values.length;
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
