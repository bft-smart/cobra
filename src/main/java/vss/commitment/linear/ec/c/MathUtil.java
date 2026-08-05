package vss.commitment.linear.ec.c;

import vss.parameters.DHRFC5114Modp2048p256;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class MathUtil {
	private final SodiumLibrary sodium;
	private final byte[] generator;
	private final BigInteger primeFieldOrder;
	private final BigInteger subPrimeFieldOrder;

	private static final byte[] ED25519_IDENTITY_POINT = new byte[] {
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};


	public MathUtil() {
		this.sodium = SodiumLibrary.INSTANCE;
		if (sodium.sodium_init() < 0) {
			throw new RuntimeException("libsodium init failed");
		}
		this.primeFieldOrder = SodiumLibrary.PRIME_FIELD_ORDER;
		this.subPrimeFieldOrder = SodiumLibrary.SUB_PRIME_FIELD_ORDER;
		BigInteger base = new BigInteger("09", 16);
		generator = bigIntegerToLittleEndian32(base);
	}

	public static void main(String[] args) {
		MathUtil util = new MathUtil();
		SecureRandom random = new SecureRandom();
		BigInteger order = new BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16);
		BigInteger p = DHRFC5114Modp2048p256.primeField;
		BigInteger rndNumber = new BigInteger(order.bitLength(), random).mod(order);
		BigInteger base = new BigInteger("09", 16);
		int nTests = 1000;

		//BigInteger v = BigInteger.valueOf(3);
		BigInteger p2 = new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
		BigInteger v = new BigInteger("a5465c9cd6fabd0f3fa3c230d134b63c2a9b535d3b1fdbf0c4df49c1c7b3df4b", 16);

		System.out.println(util.multiplyBigInteger(p));
		System.out.println(util.multiplyBigInteger(v));
		System.out.println(util.multiplyBigInteger(v).toString(16));

		System.out.println("isValid? " + util.isValidPoint(util.multiply(rndNumber)));

		//runBenchmark(util, nTests, rndNumber, base, p);
	}

	private static void runBenchmark(MathUtil util, int nTests, BigInteger rndNumber, BigInteger base, BigInteger p) {
		for (int i = 0; i < nTests; i++) {
			util.multiplyWithBase(rndNumber);
			util.multiplyBigInteger(rndNumber);
			util.multiply(rndNumber);
			base.modPow(rndNumber, p);
		}

		long startWithBase = System.nanoTime();
		for (int i = 0; i < nTests; i++) {
			util.multiplyWithBase(rndNumber);
		}
		long endWithBase = System.nanoTime();
		long startBigInteger = System.nanoTime();
		for (int i = 0; i < nTests; i++) {
			util.multiplyBigInteger(rndNumber);
		}
		long endBigInteger = System.nanoTime();

		long startMultiply = System.nanoTime();
		for (int i = 0; i < nTests; i++) {
			util.multiply(rndNumber);
		}
		long endMultiply = System.nanoTime();

		long startAdd = System.nanoTime();
		for (int i = 0; i < nTests; i++) {
			util.multiply(rndNumber);
		}
		long endAdd = System.nanoTime();

		long startJava = System.nanoTime();
		for (int i = 0; i < nTests; i++) {
			base.modPow(rndNumber, p);
		}
		long endJava = System.nanoTime();
		System.out.println("Sending base: " + (endWithBase - startWithBase) / nTests / 1_000 + " us");
		System.out.println("Using internal base: " + (endBigInteger - startBigInteger) / nTests / 1_000 + " us");
		System.out.println("Multiply: " + (endMultiply - startMultiply) / nTests / 1_000 + " us");
		System.out.println("Add: " + (endAdd - startAdd) / nTests / 1_000 + " us");
		System.out.println("Java mod p: " + (endJava - startJava) / nTests / 1_000 + " us");
	}

	public byte[] compressPoint(byte[] encodedPoint) {
		byte[] result = new byte[32];
		int status = sodium.crypto_core_ed25519_from_uniform(result, encodedPoint);
		if (status != 0) {
			throw new RuntimeException("scalar multiplication failed");
		}
		return result;
	}

	public boolean isValidPoint(byte[] point) {
		int status = sodium.crypto_core_ed25519_is_valid_point(point);
		return status == 1;
	}

	public BigInteger multiplyWithBase(BigInteger exponent) {
		byte[] encodedExponent = bigIntegerToLittleEndian32(exponent.mod(subPrimeFieldOrder));
		byte[] result = new byte[32];
		int status = sodium.crypto_scalarmult_ed25519_noclamp(result, encodedExponent, generator);
		if (status != 0) {
			throw new RuntimeException("scalar multiplication failed");
		}
		return littleEndian32ToBigInteger(result);
	}

	public BigInteger multiplyBigInteger(BigInteger exponent) {
		byte[] encodedExponent = bigIntegerToLittleEndian32(exponent.mod(subPrimeFieldOrder));
		byte[] result = new byte[32];
		int status = sodium.crypto_scalarmult_ed25519_base_noclamp(result, encodedExponent);
		if (status != 0) {
			throw new RuntimeException("scalar multiplication failed");
		}
		return littleEndian32ToBigInteger(result);
	}

	public byte[] multiply(BigInteger exponent) {
		if (exponent.equals(BigInteger.ZERO)) {
			return Arrays.copyOf(ED25519_IDENTITY_POINT, 32);
		}
		byte[] encodedExponent = bigIntegerToLittleEndian32(exponent.mod(subPrimeFieldOrder));
		byte[] result = new byte[32];
		int status = sodium.crypto_scalarmult_ed25519_base_noclamp(result, encodedExponent);
		if (status != 0) {
			throw new RuntimeException("scalar multiplication failed");
		}
		return result;
	}

	public byte[] multiply(byte[] encodedBase, BigInteger scalar) {
		if (Arrays.equals(encodedBase, ED25519_IDENTITY_POINT) || scalar.equals(BigInteger.ZERO)) {
			return Arrays.copyOf(ED25519_IDENTITY_POINT, 32);
		}
		byte[] encodedScalar = bigIntegerToLittleEndian32(scalar.mod(subPrimeFieldOrder));
		byte[] result = new byte[32];
		int status = sodium.crypto_scalarmult_ed25519_noclamp(result, encodedScalar, encodedBase);
		if (status != 0) {
			throw new RuntimeException("scalar multiplication failed");
		}
		return result;
	}

	public byte[] add(byte[] a, byte[] b) {
		byte[] result = new byte[32];
		int status = sodium.crypto_core_ed25519_add(result, a, b);
		if (status != 0) {
			throw new RuntimeException("addition failed");
		}
		return result;
	}

	public byte[] subtract(byte[] a, byte[] b) {
		byte[] result = new byte[32];
		int status = sodium.crypto_core_ed25519_sub(result, a, b);
		if (status != 0) {
			throw new RuntimeException("subtract failed");
		}
		return result;
	}

	public static byte[] bigIntegerToLittleEndian32(BigInteger value) {
		byte[] temp = value.toByteArray();  // Big-endian by default
		byte[] result = new byte[32];       // Curve25519 expects 32 bytes

		int copyLength = Math.min(temp.length, 32);
		for (int i = 0; i < copyLength; i++) {
			result[i] = temp[temp.length - 1 - i]; // Reverse for little-endian
		}

		return result;
	}

	public static BigInteger littleEndian32ToBigInteger(byte[] bytes) {
		if (bytes.length != 32) {
			throw new IllegalArgumentException("Input must be 32 bytes.");
		}

		byte[] reversed = new byte[32];
		for (int i = 0; i < 32; i++) {
			reversed[i] = bytes[31 - i];
		}

		return new BigInteger(1, reversed); // Positive BigInteger
	}

	public BigInteger getPrimeFieldOrder() {
		return primeFieldOrder;
	}

	public BigInteger getSubPrimeFieldOrder() {
		return subPrimeFieldOrder;
	}
}
