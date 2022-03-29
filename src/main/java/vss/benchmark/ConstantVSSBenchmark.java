package vss.benchmark;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.constant.KateCommitmentScheme;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.interpolation.LagrangeInterpolation;
import vss.polynomial.Polynomial;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

/**
 * @author Robin
 */
public class ConstantVSSBenchmark {
    private static final int nDecimals = 4;
    private static Cipher dataCipher;
    private static Map<Integer, BigInteger> shareholders;
    private static Set<BigInteger> corruptedShareholders;
    private static CommitmentScheme commitmentScheme;
    private static SecureRandom rndGenerator;
    private static BigInteger field;
    private static MessageDigest messageDigest;
    private static final String dataEncryptionAlgorithm = "AES";
    private static int threshold;
    private static InterpolationStrategy interpolationStrategy;
    private static Measurement mShareGeneration;
    private static Measurement mCommitmentGeneration;
    private static Measurement mShareVerification;
    private static Measurement mShareCombine;

    public static void main(String[] args) throws SecretSharingException, NoSuchPaddingException, NoSuchAlgorithmException {
        if (args.length != 7) {
            System.out.println("USAGE: ... vss.benchmark.ConstantVSSBenchmark <threshold> " +
                    "<num secrets> <secret size> <warm up iterations> <test iterations> " +
                    "<min number of faulty shareholders> <max number of faulty shareholders");
            System.exit(-1);
        }
        threshold = Integer.parseInt(args[0]);
        int n = 3 * threshold + 1;
        int quorum = 2 * threshold + 1;
        int nSecrets = Integer.parseInt(args[1]);
        int secretSize = Integer.parseInt(args[2]);
        int warmUpIterations = Integer.parseInt(args[3]);
        int nTests = Integer.parseInt(args[4]);
        int minFaultyShares = Integer.parseInt(args[5]);
        int maxFaultyShares = Integer.parseInt(args[6]);

        if (minFaultyShares < 0 || minFaultyShares > threshold || minFaultyShares > maxFaultyShares)
            throw new IllegalArgumentException("min number of faulty shareholders is out of range");

        if (maxFaultyShares > threshold)
            throw new IllegalArgumentException("max number of faulty shareholders is out of range");

        System.out.println("t = " + threshold);
        System.out.println("n = " + n);
        System.out.println("quorum = " + quorum);
        System.out.println("number of secrets = " + nSecrets);
        System.out.println("secret size = " + secretSize);
        System.out.println();

        dataCipher = Cipher.getInstance("AES");
        corruptedShareholders = new HashSet<>();
        shareholders = new HashMap<>(n);
        BigInteger[] tempShareholders = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            BigInteger shareholder = BigInteger.valueOf(i + 1);
            shareholders.put(shareholder.hashCode(), shareholder);
            tempShareholders[i] = shareholder;
        }

        commitmentScheme = new KateCommitmentScheme(threshold, tempShareholders);
        field = ((KateCommitmentScheme)commitmentScheme).getPrimeFieldOrder();
        messageDigest = MessageDigest.getInstance("SHA-256");
        rndGenerator = new SecureRandom("ola".getBytes());
        interpolationStrategy = new LagrangeInterpolation(field);

        System.out.println("Warming up (" + warmUpIterations + " iterations)");
        if (warmUpIterations > 0)
            runTests(warmUpIterations, false, minFaultyShares, maxFaultyShares, quorum,
                    nSecrets, secretSize);
        System.out.println("Running test (" + nTests + " iterations)");
        if (nTests > 0)
            runTests(nTests, true, minFaultyShares, maxFaultyShares,
                    quorum, nSecrets, secretSize);
    }

    private static void runTests(int nTests, boolean printResults, int minFaultyShares,
                                 int maxFaultyShares, int quorum, int nSecrets, int secretSize) throws SecretSharingException {
        Random rnd = new Random();

        for (int faultyShares = minFaultyShares; faultyShares <= maxFaultyShares; faultyShares++) {
            mShareGeneration = new Measurement(nTests);
            mCommitmentGeneration = new Measurement(nTests);
            mShareVerification = new Measurement(nTests);
            mShareCombine = new Measurement(nTests);

            if (printResults)
                System.out.println("============= first " + faultyShares + " faulty shares =============");
            for (int nT = 0; nT < nTests; nT++) {
                corruptedShareholders.clear();
                Set<BigInteger> corruptedShareholders = new HashSet<>();
                for (int nS = 0; nS < nSecrets; nS++) {
                    byte[] secret = new byte[secretSize];
                    rnd.nextBytes(secret);

                    OpenPublishedShares privateShares = share(secret);

                    Share[] shares = new Share[quorum];
                    int k = 0;

                    Iterator<BigInteger> it = shareholders.values().iterator();
                    while (k < quorum){
                        BigInteger shareholder = it.next();
                        if (corruptedShareholders.contains(shareholder)) {
                            continue;
                        }
                        VerifiableShare vs = extractShare(privateShares, shareholder);
                        shares[k++] = vs.getShare();
                    }

                    //corrupting share
                    if (corruptedShareholders.size() < faultyShares) {
                        shares[threshold + 1].setShare(BigInteger.ZERO);
                        corruptedShareholders.add(shares[threshold + 1].getShareholder());
                    }

                    OpenPublishedShares openShares = new OpenPublishedShares(shares, privateShares.getCommitments(), privateShares.getSharedData());

                    byte[] recoveredSecret = combine(openShares);

                    if (!Arrays.equals(recoveredSecret, secret))
                        throw new RuntimeException("Recovered Secret is different");
                }
            }

            double shareGeneration = mShareGeneration.getAverageInMillis(nDecimals);
            double commitmentsGeneration = mCommitmentGeneration.getAverageInMillis(nDecimals);
            double sharesVerification = mShareVerification.getAverageInMillis(nDecimals);
            double secretReconstruction = mShareCombine.getAverageInMillis(nDecimals);

            if (printResults) {
                System.out.println("Share generation: " + shareGeneration);
                System.out.println("Commitments generation: " + commitmentsGeneration);
                System.out.println("Share total: " + (shareGeneration + commitmentsGeneration));
                System.out.println();
                System.out.println("Shares verification: " + sharesVerification);
                System.out.println("Secret reconstruction: " + secretReconstruction);
                System.out.println("Combine total: " + (sharesVerification + secretReconstruction));
            }
        }
    }

    public static VerifiableShare extractShare(OpenPublishedShares openShares,
                                         BigInteger shareholder) throws SecretSharingException {
        Share share = openShares.getShareOf(shareholder);
        if (share == null)
            throw new SecretSharingException("Share not found");
        Commitment commitment = commitmentScheme.extractCommitment(share.getShareholder(),
                openShares.getCommitments());
        return new VerifiableShare(share, commitment, openShares.getSharedData());
    }

    private static byte[] encrypt(Cipher cipher, byte[] data, Key encryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(Cipher cipher, byte[] data, Key decryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
        return cipher.doFinal(data);
    }

    public static OpenPublishedShares share(byte[] data) throws SecretSharingException {
        try {
            mShareGeneration.start();
            //applying secret sharing scheme to encryption key
            BigInteger secretAsNumber = new BigInteger(field.bitLength() - 1, rndGenerator);

            //Encrypting data
            byte[] secretKeyBytes = messageDigest.digest(secretAsNumber.toByteArray());

            SecretKey key = new SecretKeySpec(secretKeyBytes, dataEncryptionAlgorithm);
            byte[] sharedData = encrypt(dataCipher, data, key);


            Polynomial polynomial = new Polynomial(field, threshold, secretAsNumber, rndGenerator);
            mShareGeneration.stop();

            mCommitmentGeneration.start();
            Commitment commitments = commitmentScheme.generateCommitments(polynomial);
            mCommitmentGeneration.stop();

            mShareGeneration.start();
            //calculating shares
            Share[] shares = new Share[shareholders.size()];
            BigInteger shareholder;
            Iterator<BigInteger> it = shareholders.values().iterator();
            for (int i = 0; i < shareholders.size(); i++) {
                shareholder = it.next();
                shares[i] = new Share(shareholder, polynomial.evaluateAt(shareholder));
            }
            mShareGeneration.stop();
            return new OpenPublishedShares(shares, commitments, sharedData);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new SecretSharingException("Error while creating shares.", e);
        }
    }

    public static byte[] combine(OpenPublishedShares openShares) throws SecretSharingException {
        Commitment commitments = openShares.getCommitments();
        BigInteger secretKeyAsNumber;
        mShareCombine.start();
        Share[] shares = openShares.getShares();
        Share[] minimumShares = new Share[corruptedShareholders.size() < threshold ? threshold + 2 : threshold + 1];
        for (int i = 0, j = 0; i < shares.length && j < minimumShares.length; i++) {
            Share share = shares[i];
            if (!corruptedShareholders.contains(share.getShareholder()))
                minimumShares[j++] = share;
        }
        Polynomial polynomial = new Polynomial(field, minimumShares);
        mShareCombine.stop();
        if (polynomial.getDegree() != threshold) {
            minimumShares = new Share[threshold + 1];
            int counter = 0;

            mShareVerification.start();
            commitmentScheme.startVerification(openShares.getCommitments());
            for (Share share : shares) {
                if (corruptedShareholders.contains(share.getShareholder()))
                    continue;
                boolean valid = commitmentScheme.checkValidity(share, commitments);

                if (counter <= threshold && valid)
                    minimumShares[counter++] = share;
                if (!valid)
                    corruptedShareholders.add(share.getShareholder());
            }
            commitmentScheme.endVerification();
            mShareVerification.stop();

            if (counter <= threshold)
                throw new SecretSharingException("Not enough valid shares!");
            mShareCombine.start();
            secretKeyAsNumber = interpolationStrategy.interpolateAt(BigInteger.ZERO, minimumShares);
        } else {
            mShareCombine.start();
            secretKeyAsNumber = polynomial.getConstant();
        }

        byte[] keyBytes = messageDigest.digest(secretKeyAsNumber.toByteArray());
        SecretKey secretKey = new SecretKeySpec(keyBytes, dataEncryptionAlgorithm);
        try {
            byte[] b = decrypt(dataCipher, openShares.getSharedData(), secretKey);
            mShareCombine.stop();
            return b;
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Error while decrypting secret!", e);
        }
    }
}
