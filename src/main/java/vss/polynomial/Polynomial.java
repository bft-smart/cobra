package vss.polynomial;

import vss.facade.SecretSharingException;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Represents polynomial in a finite field
 *
 * @author Robin
 */
public class Polynomial {
    private final BigInteger field;
    private BigInteger[] polynomial;
    private final int degree;

    /**
     * Generates polynomial of type a_degree*x^degree + ... + a_1*x + constant (mod field)
     * @param field Finite field
     * @param degree Degree of the polynomial
     * @param constant Constant term of this polynomial
     * @param rndGenerator Random generator to generate degree coefficients
     */
   public Polynomial(BigInteger field, int degree, BigInteger constant, SecureRandom rndGenerator) {
        this.field = field;
        this.polynomial = new BigInteger[degree + 1];
        int numBits = field.bitLength() - 1;
        for (int i = 0; i < degree; i++) {
            this.polynomial[i] = randomNumber(numBits, rndGenerator);
        }
        this.polynomial[degree] = constant;
        this.degree = degree;
    }

    public Polynomial(BigInteger field, BigInteger[] coefficients) {
        this.field = field;
        this.polynomial = Arrays.copyOf(coefficients, coefficients.length);
        this.degree = coefficients.length;
    }

    /**
     * Generates polynomial of type a_t*x^t+ ... + a_1*x + constant (mod field), where t = coefficients.length,
     * a_t,...,a_1 are coefficients[0],..., coefficients[t - 1], respectively.
     * @param field Finite field
     * @param constant Constant term of this polynomial
     * @param coefficients Coefficients of this polynomial
     */
    public Polynomial(BigInteger field, BigInteger constant, BigInteger[] coefficients) {
        this.field = field;
        this.polynomial = Arrays.copyOf(coefficients, coefficients.length + 1);
        this.polynomial[coefficients.length] = constant;
        this.degree = coefficients.length;
    }

    /**
     * Interpolates polynomials defined by shares in finite field. This polynomial has degree at most shares.length - 1.
     * This polynomial has format a_t*x^t+ ... + a_1*x + constant (mod field), where t = shares.length - 1.
     * @param field Finite field
     * @param shares Points of the polynomial.
     */
    public Polynomial(BigInteger field, Share[] shares) throws SecretSharingException {
        this.field = field;
        for (int i = 0; i < shares.length; i++) {
            BigInteger denominator = BigInteger.ONE;
            BigInteger j = shares[i].getShareholder();
            BigInteger[] numerator = null;
            for (int m = 0; m < shares.length; m++) {
                if (i == m)
                    continue;
                BigInteger[] currentNumerator = {
                        BigInteger.ONE, shares[m].getShareholder().negate()
                };
                if (numerator == null)
                    numerator = currentNumerator;
                else
                    numerator = multiply(numerator, currentNumerator);
                denominator = denominator.multiply(j.subtract(shares[m].getShareholder())).mod(field);
            }

            denominator = denominator.modInverse(field).multiply(shares[i].getShare()).mod(field);
            if (numerator == null)
                throw new SecretSharingException("This should not happen!");
            numerator = multiply(numerator, denominator);
            if (polynomial == null)
                polynomial = numerator;
            else
                polynomial = add(field, polynomial, numerator);
        }
        if (polynomial == null)
            throw new SecretSharingException("This should not happen!");
        this.degree = computeDegree(polynomial);
    }

    /**
     * This method uses Horner's method to evaluate polynomial at x.
     * @param x X value
     * @return Polynomial evaluated at x
     */
    public BigInteger evaluateAt(BigInteger x) {
        BigInteger b = polynomial[0];
        for (int i = 1; i < polynomial.length; i++) {
            b = polynomial[i].add(b.multiply(x)).mod(field);
        }
        return b;
    }

    public int getDegree() {
        return degree;
    }

    public BigInteger getConstant() {
        return polynomial[polynomial.length - 1];
    }

    public BigInteger[] getCoefficients() {
        return polynomial;
    }

    private static int computeDegree(BigInteger[] polynomial) {
        int degree = polynomial.length - 1;
        for (BigInteger coefficient : polynomial) {
            if (!coefficient.equals(BigInteger.ZERO))
                return degree;
            degree--;
        }
        return degree;
    }

    /**
     * Adds two polynomials.
     * @param p1 First polynomial
     * @param p2 Second polynomial
     * @return Return p1 with the result if p1.length >= p2.length otherwise returns p2 with the result.
     */
    public static BigInteger[] add(BigInteger field, BigInteger[] p1, BigInteger[] p2) {
        if (p1.length < p2.length) {
            BigInteger[] temp = p1;
            p1 = p2;
            p2 = temp;
        }

        for (int i = p2.length - 1, j = p1.length - 1; i >= 0; i--, j--) {
            p1[j] = p1[j].add(p2[i]).mod(field);
        }
        return p1;
    }

    public static BigInteger[] divide(BigInteger field, BigInteger[] dividend, BigInteger[] divisor) {
        int divisorDegree = computeDegree(divisor);
        int dividendDegree = computeDegree(dividend);
        BigInteger[] quotient = new BigInteger[dividendDegree - divisorDegree + 1];
        int dividendIndex = 0;
        int quotientIndex = 0;
        BigInteger[] reminder = Arrays.copyOf(dividend, dividend.length);
        while ((dividendDegree = Polynomial.computeDegree(reminder)) >= divisorDegree) {
            BigInteger t = reminder[dividendIndex].divide(divisor[0]);
            reminder = calculateReminder(field, reminder, divisor, t, dividendDegree - divisorDegree);
            quotient[quotientIndex] = t;
            quotientIndex++;
            dividendIndex++;
        }
        return quotient;
    }

    private static BigInteger[] calculateReminder(BigInteger field, BigInteger[] dividend, BigInteger[] divisor, BigInteger t, int tDegree) {
        return add(field, dividend, multiplyT(divisor, t, tDegree));
    }

    private static BigInteger[] multiplyT(BigInteger[] divisor, BigInteger t, int tDegree) {
        BigInteger[] result = new BigInteger[divisor.length + tDegree];
        Arrays.fill(result, BigInteger.ZERO);
        for (int i = 0; i < divisor.length; i++) {
            result[i] = t.multiply(divisor[i]).negate();

        }
        return result;
    }

    /**
     * Multiplies to polynomials or polynomial with constant.
     * @param p1 First polynomial
     * @param p2 Second polynomial or a constant
     * @return Product of p1 with p2
     */
    private BigInteger[] multiply(BigInteger[] p1, BigInteger... p2) {
        BigInteger[] result = new BigInteger[p1.length + p2.length - 1];
        Arrays.fill(result, BigInteger.ZERO);
        for (int i = 0; i < p1.length; i++) {
            for (int j = 0; j < p2.length; j++) {
                result[i + j] = result[i + j].add(p1[i].multiply(p2[j])).mod(field);
            }
        }
        return result;
    }

    /**
     * Generate random number n. n > 0 && n <= 2^numBits.
     * @param numBits Maximum size length of the random number in bits
     * @param rndGenerator Generator used to generate random number
     * @return Random number
     */
    private BigInteger randomNumber(int numBits, SecureRandom rndGenerator) {
        BigInteger rndBig = new BigInteger(numBits, rndGenerator);
        if (rndBig.compareTo(BigInteger.ZERO) == 0)
            rndBig = rndBig.add(BigInteger.ONE);
        return rndBig;
    }

    @Override
    public String toString() {
        int t = polynomial.length - 1;
        StringBuilder sb = new StringBuilder();
        boolean start = false;
        for (BigInteger bigInteger : polynomial) {
            if (!start && !bigInteger.equals(BigInteger.ZERO))
                start = true;
            if (start && t != 0) {
                sb.append(bigInteger);
                sb.append("x^");
                sb.append(t);
                sb.append(" + ");
            } else if (t == 0) {
                sb.append(bigInteger);
            }
            t--;
        }
        return sb.toString();
    }
}
