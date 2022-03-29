package vss.commitment;

import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Map;

/**
 * Interface that represent Verifiable Secret Sharing scheme
 *
 * @author Robin
 */
public interface CommitmentScheme {
    /**
     * Generates commitment for given polynomial
     * @param polynomial Polynomial
     * @param additionalShareholders Additional shareholders to commit to
     * @return Commitments
     */
    Commitment generateCommitments(Polynomial polynomial,
                                   BigInteger... additionalShareholders);


    /**
     * Start verification of multiple shares
     *
     * @param commitment Commitment
     */
    void startVerification(Commitment commitment);

    /**
     * Ends context of multiple verification of shares to start next context
     */
    void endVerification();

    /**
     * Adds the new shareholder to the current set of shareholders
     * @param shareholder Shareholder
     */
    void addShareholder(BigInteger shareholder);

    /**
     * Removes the shareholder if it exists in the current set of shareholders
     * @param shareholder Shareholder
     */
    void removeShareholder(BigInteger shareholder);

    /**
     * Checks if given share is valid
     * @param share Share to verify
     * @param commitment Commitment of the polynomial
     * @return True if share is valid, false otherwise
     */
    boolean checkValidity(Share share, Commitment commitment);

    /**
     * Check if multiple polynomials have same share without knowing share
     * @param x Shareholder ID
     * @param commitments Commitment of the polynomial containing x's commitment
     * @return True if all the polynomials contain same share, false otherwise
     */
    boolean checkValidityOfPolynomialsProperty(BigInteger x, Commitment... commitments);

    /**
     * Checks if given share is valid, without requiring to call startVerification to precompute some values
     * @param share Share to verify
     * @param commitment Commitment of the polynomial
     * @return True if share is valid, false otherwise
     */
    boolean checkValidityWithoutPreComputation(Share share, Commitment commitment);

    /**
     * Add multiple commitments
     * @param commitments Commitments to add
     * @return Sum of given commitments
     * @throws SecretSharingException If commitments have different size or type
     */
    Commitment sumCommitments(Commitment... commitments) throws SecretSharingException;

    /**
     * Compute c1 - c2
     * @param c1 Commitment
     * @param c2 Commitment
     * @return c1 - c2
     * @throws SecretSharingException If commitments have different size
     */
    Commitment subtractCommitments(Commitment c1, Commitment c2) throws SecretSharingException;

    /**
     * Given global commitment, extract commitment for a specific shareholder
     * @param shareholder Shareholder
     * @param commitment Global commitment
     * @return Commitment of the shareholder or null if there is any
     */
    Commitment extractCommitment(BigInteger shareholder, Commitment commitment);

    /**
     * Returns combined commitments of the same secret
     * @param commitments Shareholders and corresponding commitment of the same secret
     * @return Combined commitment or null if commitments is empty
     */
    Commitment combineCommitments(Map<BigInteger, Commitment> commitments);

    /**
     * Returns recovered commitment of newShareholder to verify its share of the same
     * secret
     * @param newShareholder New shareholder
     * @param commitments Shareholders and corresponding commitment of the same secret
     * @return Recovered commitments for share or null if commitments is empty
     */
    Commitment recoverCommitment(BigInteger newShareholder, Map<BigInteger, Commitment> commitments) throws SecretSharingException;

    Commitment readCommitment(ObjectInput in) throws IOException, ClassNotFoundException;

    void writeCommitment(Commitment commitment, ObjectOutput out) throws IOException;

}
