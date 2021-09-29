package confidential.client;

import bftsmart.reconfiguration.views.View;
import confidential.CobraConfidentialityScheme;
import confidential.encrypted.EncryptedPublishedShares;
import vss.facade.Mode;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class ClientConfidentialityScheme extends CobraConfidentialityScheme {

    public ClientConfidentialityScheme(View view) throws SecretSharingException {
        super(view);
    }

    /**
     * Returns encrypted shares of the secret
     * @param secret Secret to share
     * @return Encrypted shares
     * @throws SecretSharingException See {@link vss.facade.VSSFacade}.share()
     */
    public EncryptedPublishedShares share(byte[] secret, Mode mode) throws SecretSharingException {
        OpenPublishedShares openShares = vss.share(secret, mode, threshold);

        Share[] shares = openShares.getShares();
        Map<Integer, byte[]> encryptedShares = new HashMap<>(shares.length);

        BigInteger shareholder;
        int server;
        byte[] encryptedShare;
        for (Share share : shares) {
            shareholder = share.getShareholder();
            server = getProcess(shareholder);
            encryptedShare = encryptShareFor(server, share);
            encryptedShares.put(server, encryptedShare);
        }

        return new EncryptedPublishedShares(encryptedShares, openShares.getCommitments(),
                openShares.getSharedData());
    }

    public byte[] combine(OpenPublishedShares shares, Mode mode) throws SecretSharingException {
        byte[] b = vss.combine(shares, mode, threshold);
        if (b == null || b.length == 0)
            System.out.println("Confidential data is null");
        return b;
    }
}
