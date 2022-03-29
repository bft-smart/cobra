package vss.interpolation;

import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;

/**
 * Exposes methods that can be invoked to interpolate polynomial and compute point on it
 *
 * @author Robin
 */
public interface InterpolationStrategy {

    /**
     * This method interpolates polynomial of degree shares.length - 1 and returns value evaluated at x.
     * @param x Value of x
     * @param shares Shares used to interpolate polynomial
     * @return Value of y
     */
    BigInteger interpolateAt(BigInteger x, Share[] shares);

    /**
     * This method interpolates polynomial using share.length and returns it. The polynomial will have at most degree shares.length - 1
     * @param shares Shares used to interpolate polynomial
     * @return Polynomial
     */
    Polynomial interpolate(Share[] shares) throws SecretSharingException;

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

}
