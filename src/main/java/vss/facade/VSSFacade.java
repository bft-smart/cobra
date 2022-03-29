package vss.facade;

import vss.Constants;
import vss.secretsharing.VerifiableSecretSharing;

import java.math.BigInteger;
import java.util.Properties;

/**
 * This class exposes methods to share a confidential data and reconstruct it back.
 * Confidential data is encrypted using random encryption key and shares are of encryption key (Mode.LARGE_SECRET).
 * Or shares are directly computed using confidential data (Mode.SMALL_SECRET).
 *
 * TODO: this class should be singleton
 *
 * @author Robin
 */
public final class VSSFacade extends VerifiableSecretSharing {

    /**
     * Creates object of this class
     * @param properties Properties containing values for tags containing in the {@link Constants} class
     * @param shareholders Ids of shareholders for secret sharing scheme. Each id must be greater than 0
     * @throws SecretSharingException  When fails to create object
     */
    public VSSFacade(Properties properties,
                     BigInteger[] shareholders) throws SecretSharingException {
        super(properties, shareholders);
    }
}
