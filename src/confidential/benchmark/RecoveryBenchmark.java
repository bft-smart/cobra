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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author Robin
 */
public class RecoveryBenchmark {
    private static final BigInteger keyNumber = new BigInteger("937810634060551071826485204471949219646466658841719067506");
    private static SecureRandom rndGenerator;
    private static int threshold;
    private static BigInteger[] shareholders;
    private static int n;
    private static Map<BigInteger, Key> keys;
    private static boolean verifyCorrectness;
    private static int nProcessingThreads;

    public static void main(String[] args) throws SecretSharingException, InterruptedException {
        if (args.length != 7) {
            System.out.println("USAGE: ... confidential.benchmark.RecoveryBenchmark " +
                    "<threshold> <num secrets> <warm up iterations> <test iterations> " +
                    "<num processing threads> <verify correctness> <commitment scheme -> linear|constant>");
            System.exit(-1);
        }

        threshold = Integer.parseInt(args[0]);
        int nSecrets = Integer.parseInt(args[1]);
        int warmUpIterations = Integer.parseInt(args[2]);
        int testIterations = Integer.parseInt(args[3]);
        nProcessingThreads = Integer.parseInt(args[4]);
        verifyCorrectness = Boolean.parseBoolean(args[5]);
        String commitmentSchemeName = args[6];

        n = 3 * threshold + 1;

        System.out.println("t = " + threshold);
        System.out.println("n = " + n);
        System.out.println("number of secrets = " + nSecrets);
        System.out.println("commitment scheme = " + commitmentSchemeName);
        System.out.println();

        shareholders = new BigInteger[n];
        keys = new HashMap<>(n);
        for (int i = 0; i < n; i++) {
            BigInteger shareholder = BigInteger.valueOf(i + 1);
            shareholders[i] = shareholder;
            keys.put(shareholder, new SecretKeySpec(keyNumber.toByteArray(), "AES"));
        }

        Configuration configuration = Configuration.getInstance();

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(threshold));
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
        VSSFacade vssFacade = new VSSFacade(properties, shareholders);

        System.out.println("Warming up (" + warmUpIterations + " iterations)");
        if (warmUpIterations > 0)
            runTests(warmUpIterations, false, nSecrets, vssFacade);
        System.out.println("Running test (" + testIterations + " iterations)");
        if (testIterations > 0)
            runTests(testIterations, true, nSecrets, vssFacade);
    }

    private static void runTests(int nTests, boolean printResults, int nSecrets,
                                 VSSFacade vssFacade) throws SecretSharingException, InterruptedException {
        int recoveryShareholderIndex = 0;
        BigInteger field = vssFacade.getField();
        CommitmentScheme commitmentScheme = vssFacade.getCommitmentScheme();

        Polynomial r =
                createRecoveryPolynomialFor(recoveryShareholderIndex, vssFacade);

        Commitment rCommitment = commitmentScheme.generateCommitments(r);

        BigInteger[] rPoints = generateShares(shareholders, r);

        byte[] secret = new byte[1024];
        rndGenerator.nextBytes(secret);
        PrivatePublishedShares privateShares = vssFacade.share(secret, keys);

        Set<BigInteger> corruptedServers = new HashSet<>(threshold);

        long start, end;
        long[] recoveryShareGenerationTimes = new long[nTests];
        long[] sharesRecoveryTimes = new long[nTests];
        long[] commitmentsRecoveryTimes = new long[nTests];
        long[] allTimes = new long[nTests];

        for (int nT = 0; nT < nTests; nT++) {
            corruptedServers.clear();
            long recoveryShareGenerationTime = 0;
            long sharesRecoveryTime = 0;
            long commitmentsRecoveryTime = 0;
            long allTimeStart, allTimeEnd;
            allTimeStart = System.nanoTime();

            //Extracting shares
            VerifiableShare[][] allVerifiableShares = new VerifiableShare[nSecrets][];
            for (int nS = 0; nS < nSecrets; nS++) {
                VerifiableShare[] verifiableShares = new VerifiableShare[n];
                for (int i = 0; i < n; i++) {
                    if (i == recoveryShareholderIndex)
                        continue;
                    verifiableShares[i] = vssFacade.extractShare(privateShares, shareholders[i],
                            keys.get(shareholders[i]));
                }
                allVerifiableShares[nS] = verifiableShares;
            }
            byte[] sharedData = allVerifiableShares[0][(recoveryShareholderIndex + 1) % n].getSharedData();

            //creating recovery shares
            Share[][] allRecoveryShares = new Share[nSecrets][];
            for (int nS = 0; nS < nSecrets; nS++) {
                VerifiableShare[] verifiableShares = allVerifiableShares[nS];
                Share[] recoveryShares = new Share[n - 1];
                for (int i = 0, j = 0; i < n; i++) {
                    if (i == recoveryShareholderIndex)
                        continue;
                    VerifiableShare vs = verifiableShares[i];
                    if (i == (recoveryShareholderIndex + 1) % n) {
                        start = System.nanoTime();
                        recoveryShares[j++] = new Share(vs.getShare().getShareholder(),
                                vs.getShare().getShare().add(rPoints[i]).mod(field));
                        end = System.nanoTime();
                        recoveryShareGenerationTime += end - start;
                        continue;
                    }
                    recoveryShares[j++] = new Share(vs.getShare().getShareholder(),
                            vs.getShare().getShare().add(rPoints[i]).mod(field));
                }
                allRecoveryShares[nS] = recoveryShares;
            }

            //Recovering commitments
            ExecutorService executor = Executors.newFixedThreadPool(nProcessingThreads);
            CountDownLatch commitmentRecoveryCounter = new CountDownLatch(nSecrets);
            Commitment[] allRecoveredCommitment = new Commitment[nSecrets];
            Map<BigInteger, Commitment>[] allRecoveryCommitments = new Map[nSecrets];
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                int finalNS = nS;
                VerifiableShare[] verifiableShares = allVerifiableShares[nS];
                executor.execute(() -> {
                    int minNumberOfCommitments = corruptedServers.size() >= threshold ? threshold : threshold + 1;
                    Map<BigInteger, Commitment> validCommitments = new HashMap<>(minNumberOfCommitments);
                    for (int i = 0; i < n; i++) {
                        if (i == recoveryShareholderIndex)
                            continue;
                        validCommitments.put(shareholders[i],
                                verifiableShares[i].getCommitments());
                        if (validCommitments.size() == minNumberOfCommitments)
                            break;
                    }
                    Commitment recoveredCommitment;
                    try {
                        recoveredCommitment =
                                commitmentScheme.recoverCommitment(shareholders[recoveryShareholderIndex], validCommitments);
                    } catch (SecretSharingException e) {
                        System.err.println("Invalid Commitments");
                        validCommitments.clear();
                        recoveredCommitment = null;
                        System.exit(-1);
                    }
                    allRecoveryCommitments[finalNS] = validCommitments;
                    allRecoveredCommitment[finalNS] = recoveredCommitment;
                    commitmentRecoveryCounter.countDown();
                });
            }
            executor.shutdown();
            commitmentRecoveryCounter.await();
            end = System.nanoTime();
            commitmentsRecoveryTime += end - start;

            //Recovering shares
            executor = Executors.newFixedThreadPool(nProcessingThreads);
            CountDownLatch shareRecoveryCounter = new CountDownLatch(nSecrets);
            VerifiableShare[] allRecoveredShares = new VerifiableShare[nSecrets];
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                int finalNS = nS;
                Map<BigInteger, Commitment> recoveryCommitments = allRecoveryCommitments[nS];
                Commitment recoveredCommitment = allRecoveredCommitment[nS];
                Share[] recoveryShares = allRecoveryShares[nS];
                executor.execute(() -> {
                    try {
                        Share[] recoveringShares =
                                new Share[threshold + (corruptedServers.size() < threshold ? 2
                                        : 1)];

                        Map<BigInteger, Share> allRecoveringShares = new HashMap<>();
                        for (int i = 0, j = 0; i < recoveryShares.length; i++) {
                            Share share = recoveryShares[i];
                            if (share == null)
                                continue;
                            if (j < recoveringShares.length && !corruptedServers.contains(share.getShareholder())) {
                                recoveringShares[j++] = share;
                            }
                            allRecoveringShares.put(share.getShareholder(), share);
                        }

                        Polynomial polynomial = new Polynomial(field, recoveringShares);
                        BigInteger shareNumber;
                        if (polynomial.getDegree() != threshold) {
                            recoveringShares = new Share[threshold + 1];
                            Commitment combinedCommitment =
                                    commitmentScheme.combineCommitments(recoveryCommitments);
                            Commitment verificationCommitment =
                                    commitmentScheme.sumCommitments(rCommitment,
                                            combinedCommitment);
                            commitmentScheme.startVerification(verificationCommitment);
                            int j = 0;
                            for (Map.Entry<BigInteger, Share> entry : allRecoveringShares.entrySet()) {
                                if (commitmentScheme.checkValidity(entry.getValue(), verificationCommitment)) {
                                    recoveringShares[j++] = entry.getValue();
                                } else {
                                    corruptedServers.add(entry.getValue().getShareholder());
                                }
                            }
                            commitmentScheme.endVerification();
                            shareNumber =
                                    vssFacade.getInterpolationStrategy().interpolateAt(shareholders[recoveryShareholderIndex], recoveringShares);
                        } else {
                            shareNumber =
                                    polynomial.evaluateAt(shareholders[recoveryShareholderIndex]);
                        }
                        Share recoveredShare = new Share(shareholders[recoveryShareholderIndex], shareNumber);
                        allRecoveredShares[finalNS] =
                                new VerifiableShare(recoveredShare, recoveredCommitment, sharedData);
                        shareRecoveryCounter.countDown();
                    } catch (SecretSharingException e) {
                        e.printStackTrace();
                    }
                });
            }
            executor.shutdown();
            shareRecoveryCounter.await();
            end = System.nanoTime();
            sharesRecoveryTime += end - start;

            //Verifying correction
            if (verifyCorrectness) {
                for (int nS = 0; nS < nSecrets; nS++) {
                    VerifiableShare[] verifiableShares = allVerifiableShares[nS];
                    verifiableShares[recoveryShareholderIndex] = allRecoveredShares[nS];
                    Share[] shares = new Share[n];
                    Map<BigInteger, Commitment> commitments = new HashMap<>(n);
                    for (int i = 0; i < n; i++) {
                        VerifiableShare vs = verifiableShares[i];
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

            recoveryShareGenerationTimes[nT] = recoveryShareGenerationTime;
            sharesRecoveryTimes[nT] = sharesRecoveryTime;
            commitmentsRecoveryTimes[nT] = commitmentsRecoveryTime;
            allTimes[nT] = allTimeEnd - allTimeStart;
        }

        if (printResults) {
            double recoveryShareGeneration = computeAverage(recoveryShareGenerationTimes) / 1_000_000.0;
            double sharesRecovery = computeAverage(sharesRecoveryTimes) / 1_000_000.0;
            double commitmentsRecovery = computeAverage(commitmentsRecoveryTimes) / 1_000_000.0;
            double allTimeAvg = computeAverage(allTimes) / 1_000_000.0;

            System.out.println("Recovery share generation: " + recoveryShareGeneration +  " ms");
            System.out.println("Share recovery: " + sharesRecovery + " ms");
            System.out.println("Commitment recovery: " + commitmentsRecovery + " ms");
            System.out.println("Recovery total: " + (recoveryShareGeneration + sharesRecovery
                    + commitmentsRecovery) + " ms");
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

    private static Polynomial createRecoveryPolynomialFor(int recoveryShareholderIndex, VSSFacade vssFacade) {
        Polynomial tempPolynomial = new Polynomial(vssFacade.getField(), threshold,
                BigInteger.ZERO, rndGenerator);
        BigInteger independentTerm =
                tempPolynomial.evaluateAt(shareholders[recoveryShareholderIndex]).negate();
        BigInteger[] tempCoefficients = tempPolynomial.getCoefficients();
        BigInteger[] coefficients = Arrays.copyOfRange(tempCoefficients,
                tempCoefficients.length - tempPolynomial.getDegree() - 1,
                tempCoefficients.length - 1);

        return new Polynomial(vssFacade.getField(), independentTerm, coefficients);
    }
}
