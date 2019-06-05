package confidential.benchmark;

import bftsmart.reconfiguration.views.View;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static confidential.Configuration.*;
import static confidential.Configuration.shareEncryptionAlgorithm;

public class SecretSharingBenchmark {
    private static int nTests = 50;
    private static int threshold;
    private static int n;
    private static Map<BigInteger, Key> keys;
    private static VSSFacade vss;

    public static void main(String[] args) throws SecretSharingException {
        threshold = Integer.parseInt(args[0]);
        n = 3 * threshold + 1;
        int[] currentViewProcesses = new int[n];
        for (int i = 0; i < n; i++) {
            currentViewProcesses[i] = i;
        }
        keys = new HashMap<>(currentViewProcesses.length);
        BigInteger[] shareholders = new BigInteger[currentViewProcesses.length];
        for (int i = 0; i < currentViewProcesses.length; i++) {
            shareholders[i] = BigInteger.valueOf(currentViewProcesses[i] + 1);
            keys.put(shareholders[i], new SecretKeySpec(defaultKeys[i].toByteArray(), shareEncryptionAlgorithm));
        }

        vss = new VSSFacade(p, generator, field, shareholders, dataEncryptionAlgorithm,
                dataEncryptionKeySize, shareEncryptionAlgorithm);
        byte[] secret = new byte[1024];
        new Random().nextBytes(secret);
        System.out.println("Running test for t = " + threshold + " | n = " + n);
        for (int i = 0; i < nTests; i++) {
            PrivatePublishedShares privateShares = share(secret);
            Share[] shares = new Share[shareholders.length];
            for (int j = 0; j < shareholders.length; j++) {
                VerifiableShare vs = vss.extractShare(privateShares, shareholders[j], keys.get(shareholders[j]));
                shares[j] = vs.getShare();
            }
            OpenPublishedShares openPublishedShares = new OpenPublishedShares(shares, privateShares.getCommitments(), privateShares.getSharedData());
            byte[] recoveredSecret = combine(openPublishedShares);
            if (!Arrays.equals(recoveredSecret, secret))
                throw new RuntimeException("Recovered Secret is different");
        }
    }

    public static PrivatePublishedShares share(byte[] secret) throws SecretSharingException {
        return vss.share(threshold, secret, keys);
    }


    public static byte[] combine(OpenPublishedShares shares) throws SecretSharingException {
        return vss.combine(shares);
    }
}
