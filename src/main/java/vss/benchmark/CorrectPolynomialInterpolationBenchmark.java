package vss.benchmark;

import vss.commitment.CommitmentScheme;
import vss.commitment.linear.FeldmanCommitmentScheme;
import vss.commitment.linear.LinearCommitments;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

public class CorrectPolynomialInterpolationBenchmark {
    private static final int nTests = 25;
    private static final int nDecimals = 4;
    private static final BigInteger p = new BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16);
    private static final BigInteger field = new BigInteger("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16);
    private static final BigInteger generator = new BigInteger("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16);
    private static final SecureRandom rndGenerator = new SecureRandom("ola".getBytes());
    private static Set<BigInteger> blackList;

    public static void main(String[] args) throws SecretSharingException {
        int threshold = args.length == 0 ? 1 : Integer.parseInt(args[0]);
        int nSecrets = args.length == 0 ? 1 : Integer.parseInt(args[1]);

        System.out.println("Warming up");
        runTests(false, threshold, nSecrets);
        System.out.println("Running test");
        runTests(true, threshold, nSecrets);
    }

    private static void runTests(boolean printResults, int threshold, int nSecrets) throws SecretSharingException {
        for (int faultyShares = 0; faultyShares <= threshold; faultyShares++) {
            if (printResults)
                System.out.println("============= first " + faultyShares + " faulty shares =============");

            CommitmentScheme commitmentScheme = new FeldmanCommitmentScheme(p, generator);
            Measurement mCommitmentsGeneration = new Measurement(nTests);
            Measurement mFeldmanReconstruction = new Measurement(nTests);
            Measurement mMixSchemeReconstruction = new Measurement(nTests);
            Share[] shares;

            int bftQuorum = 2 * threshold + 1;

            for (int tn = 0; tn < nTests; tn++) {
                blackList = new HashSet<>();

                for (int nS = 0; nS < nSecrets; nS++) {
                    Polynomial polynomial = new Polynomial(field, threshold, BigInteger.TEN, rndGenerator);

                    mCommitmentsGeneration.start();
                    LinearCommitments commitments = (LinearCommitments)commitmentScheme.generateCommitments(polynomial);
                    mCommitmentsGeneration.stop();

                    shares = new Share[bftQuorum];
                    for (int i = 0; i < bftQuorum; i++) {
                        BigInteger shareholder = BigInteger.valueOf(i + 1);
                        shares[i] = new Share(shareholder, polynomial.evaluateAt(shareholder));
                    }
                    corruptFirstFShares(faultyShares, shares);

                    mFeldmanReconstruction.start();
                    Polynomial feldmanReconstructedPolynomial = feldmanReconstruction(threshold, commitments, shares, commitmentScheme);
                    mFeldmanReconstruction.stop();

                    comparePolynomials(bftQuorum, polynomial, feldmanReconstructedPolynomial);

                    mMixSchemeReconstruction.start();
                    Polynomial mixSchemeReconstructedPolynomial = mixSchemeReconstruction(threshold, commitments, shares, commitmentScheme);
                    mMixSchemeReconstruction.stop();

                    comparePolynomials(bftQuorum, polynomial, mixSchemeReconstructedPolynomial);
                }
            }

            if (printResults) {
                System.out.println("Commitments generation: " + mCommitmentsGeneration.getAverageInMillis(nDecimals) + " ms");
                System.out.println("Feldman reconstruction: " + mFeldmanReconstruction.getAverageInMillis(nDecimals) + " ms");
                System.out.println("Mix scheme reconstruction: " + mMixSchemeReconstruction.getAverageInMillis(nDecimals) + " ms");
            }
        }
    }

    private static void comparePolynomials(int bftQuorum, Polynomial polynomial, Polynomial feldmanReconstructedPolynomial) {
        for (int i = 0; i < bftQuorum; i++) {
            BigInteger shareholder = BigInteger.valueOf(i + 1);
            if (!polynomial.evaluateAt(shareholder).equals(feldmanReconstructedPolynomial.evaluateAt(shareholder)))
                throw new RuntimeException("Different polynomial");
        }
    }

    private static Polynomial mixSchemeReconstruction(int threshold, LinearCommitments commitments, Share[] shares,
                                                      CommitmentScheme commitmentScheme) throws SecretSharingException {
        Share[] minimumShares = new Share[blackList.size() < threshold ? threshold + 2 : threshold + 1];

        for (int i = 0, j = 0; i < shares.length && j < minimumShares.length; i++) {
            Share share = shares[i];
            if (!blackList.contains(share.getShareholder()))
                minimumShares[j++] = share;
        }

        Polynomial polynomial = new Polynomial(field, minimumShares);
        if (polynomial.getDegree() != threshold) {
            minimumShares = new Share[threshold + 1];
            int counter = 0;
            for (Share share : shares) {
                if (blackList.contains(share.getShareholder()))
                    continue;
                boolean valid = commitmentScheme.checkValidity(share, commitments);

                if (counter <= threshold && valid)
                    minimumShares[counter++] = share;
                if (!valid)
                    blackList.add(share.getShareholder());
                if (counter > threshold)
                    break;
            }
            polynomial = new Polynomial(field, minimumShares);
        }
        return polynomial;
    }

    private static Polynomial feldmanReconstruction(int threshold, LinearCommitments commitments, Share[] shares,
                                                    CommitmentScheme commitmentScheme) throws SecretSharingException {
        Share[] minimumShares = new Share[threshold + 1];
        int counter = 0;
        for (Share share : shares) {
            if (counter > threshold)
                break;
            if (commitmentScheme.checkValidity(share, commitments))
                minimumShares[counter++] = share;
        }

        return new Polynomial(field, minimumShares);
    }

    private static void corruptFirstFShares(int f, Share[] shares) {
        for (int i = 0; i < f; i++) {
            shares[i].setShare(BigInteger.ZERO);
        }
    }
}
