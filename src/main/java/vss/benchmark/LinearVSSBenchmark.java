package vss.benchmark;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.linear.FeldmanCommitmentScheme;
import vss.commitment.linear.LinearCommitments;
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

public class LinearVSSBenchmark {
    private static final int nDecimals = 4;
    private static final BigInteger p = new BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16);
    private static final BigInteger field = new BigInteger("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16);
    private static final BigInteger generator = new BigInteger("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16);
    private static Map<Integer, BigInteger> shareholders;
    private static final String dataEncryptionAlgorithm = "AES";
    private static Cipher dataCipher;
    private static SecureRandom rndGenerator;
    private static CommitmentScheme commitmentScheme;
    private static InterpolationStrategy interpolationStrategy;
    private static Set<BigInteger> corruptedShareholders;
    private static Measurement mShareGeneration;
    private static Measurement mCommitmentsGeneration;
    private static Measurement mShareValidation;
    private static Measurement mSharesCombine;
    private static int threshold;
    private static MessageDigest messageDigest;

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, SecretSharingException {
        if (args.length != 7) {
            System.out.println("USAGE: ... vss.benchmark.LinearVSSBenchmark " +
                    "<threshold> " +
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

        rndGenerator = new SecureRandom("ola".getBytes());
        dataCipher = Cipher.getInstance("AES");
        commitmentScheme = new FeldmanCommitmentScheme(p, generator);
        interpolationStrategy = new LagrangeInterpolation(field);
        messageDigest = MessageDigest.getInstance("SHA-256");
        corruptedShareholders = new HashSet<>();

        System.out.println("t = " + threshold);
        System.out.println("n = " + n);
        System.out.println("quorum = " + quorum);
        System.out.println("number of secrets = " + nSecrets);
        System.out.println("secret size = " + secretSize);
        System.out.println();

        shareholders = new HashMap<>(n);
        for (int i = 0; i < n; i++) {
            shareholders.put(i, BigInteger.valueOf(i + 1));
        }


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
            if (printResults) {
                System.out.println("============= first " + faultyShares + " faulty shares =============");
            }
            mShareGeneration = new Measurement(nTests);
            mCommitmentsGeneration = new Measurement(nTests);
            mShareValidation = new Measurement(nTests);
            mSharesCombine = new Measurement(nTests);

            for (int tn = 0; tn < nTests; tn++) {
                corruptedShareholders.clear();
                Set<BigInteger> corruptedShareholders = new HashSet<>();
                for (int j = 0; j < nSecrets; j++) {
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
            double commitmentsGeneration = mCommitmentsGeneration.getAverageInMillis(nDecimals);
            double sharesVerification = mShareValidation.getAverageInMillis(nDecimals);
            double secretReconstruction = mSharesCombine.getAverageInMillis(nDecimals);

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

    private static OpenPublishedShares share(byte[] data) throws SecretSharingException {
        try {
            mShareGeneration.start();
            //Encrypting data
            BigInteger secretAsNumber = new BigInteger(field.bitLength() - 1, rndGenerator);
            byte[] secretKeyBytes = messageDigest.digest(secretAsNumber.toByteArray());

            SecretKey key = new SecretKeySpec(secretKeyBytes, dataEncryptionAlgorithm);
            byte[] sharedData = encrypt(dataCipher, data, key);

            //applying secret sharing scheme to encryption key
            Polynomial polynomial = new Polynomial(field, threshold, secretAsNumber, rndGenerator);
            mShareGeneration.stop();
            mCommitmentsGeneration.start();
            Commitment commitments = commitmentScheme.generateCommitments(polynomial);
            //Polynomial polynomial = createPolynomialOfSecret(secretAsNumber, coefficients);
            mCommitmentsGeneration.stop();
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

    private static VerifiableShare extractShare(OpenPublishedShares openShares, BigInteger shareholder) throws SecretSharingException {
        Share share = openShares.getShareOf(shareholder);
        if (share == null)
            throw new SecretSharingException("Share not found");
        return new VerifiableShare(share, openShares.getCommitments(), openShares.getSharedData());
    }

    private static byte[] combine(OpenPublishedShares openShares) throws SecretSharingException {
        LinearCommitments commitments = (LinearCommitments) openShares.getCommitments();
        int threshold = commitments.getCommitments().length - 1;
        BigInteger secretKeyAsNumber;
        mSharesCombine.start();
        Share[] shares = openShares.getShares();
        Share[] minimumShares = new Share[corruptedShareholders.size() < threshold ? threshold + 2 : threshold + 1];
        for (int i = 0, j = 0; i < shares.length && j < minimumShares.length; i++) {
            Share share = shares[i];
            if (!corruptedShareholders.contains(share.getShareholder()))
                minimumShares[j++] = share;
        }
        Polynomial polynomial = new Polynomial(field, minimumShares);
        mSharesCombine.stop();
        if (polynomial.getDegree() != threshold) {
            minimumShares = new Share[threshold + 1];
            int counter = 0;
            mShareValidation.start();
            for (Share share : shares) {
                if (corruptedShareholders.contains(share.getShareholder()))
                    continue;

                boolean valid = commitmentScheme.checkValidity(share, commitments);

                if (counter <= threshold && valid)
                    minimumShares[counter++] = share;
                if (!valid)
                    corruptedShareholders.add(share.getShareholder());
            }
            mShareValidation.stop();

            if (counter <= threshold) {
                throw new SecretSharingException("Not enough valid shares!");
            }
            mSharesCombine.start();
            secretKeyAsNumber = interpolationStrategy.interpolateAt(BigInteger.ZERO, minimumShares);
        } else {
            mSharesCombine.start();
            secretKeyAsNumber = polynomial.getConstant();
        }

        byte[] keyBytes = messageDigest.digest(secretKeyAsNumber.toByteArray());
        SecretKey secretKey = new SecretKeySpec(keyBytes, dataEncryptionAlgorithm);
        try {
            byte[] b = decrypt(dataCipher, openShares.getSharedData(), secretKey);
            mSharesCombine.stop();
            return b;
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Error while decrypting secret!", e);
        }
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
}
