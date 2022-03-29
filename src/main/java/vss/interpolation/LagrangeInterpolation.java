package vss.interpolation;

import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;

/**
 * This class implements Lagrange Interpolation equations.
 * All the computations are done on a finite field
 *
 * @author Robin
 */
public class LagrangeInterpolation implements InterpolationStrategy {
    private final BigInteger field;

    /**
     * Instantiates object to allow interpolation of polynomials and computation of points on it in finite field filed
     * @param field Finite field
     */
    public LagrangeInterpolation(BigInteger field) {
        this.field = field;
    }

    /**
     * Interpolated a polynomial F and returns value y of point (x,y) on F
     * @param x Value of x
     * @param shares Shares used to interpolate polynomial
     * @return Value y
     */
    @Override
    public BigInteger interpolateAt(BigInteger x, Share[] shares){
        BigInteger result = BigInteger.ZERO;

        for (Share i : shares) {
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;
            for (Share j : shares) {
                if (i.getShareholder().equals(j.getShareholder()))
                    continue;
                numerator = numerator.multiply(x.subtract(j.getShareholder()));
                denominator = denominator.multiply(i.getShareholder().subtract(j.getShareholder()));
            }
            denominator = denominator.modInverse(field);
            result = result.add(numerator.multiply(denominator).multiply(i.getShare())).mod(field);
        }

        return result;
    }

    /**
     * Returns interpolated polynomial
     * @param shares Shares used to interpolate polynomial
     * @return Return interpolate polynomial
     * @throws SecretSharingException When fails to interpolate polynomial
     */
    @Override
    public Polynomial interpolate(Share[] shares) throws SecretSharingException {
        return new Polynomial(field, shares);
    }

    @Override
    public void addShareholder(BigInteger shareholder) {

    }

    @Override
    public void removeShareholder(BigInteger shareholder) {

    }
}
