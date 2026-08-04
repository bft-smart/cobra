package vss.commitment.linear.ec.c;

import com.sun.jna.Library;
import com.sun.jna.Native;

import java.math.BigInteger;

public interface SodiumLibrary extends Library {
	//https://std.neuromancer.sk/other/Ed25519
	BigInteger PRIME_FIELD_ORDER = new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
	BigInteger SUB_PRIME_FIELD_ORDER = new BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16);
	SodiumLibrary INSTANCE = Native.load("sodium", SodiumLibrary.class);

	int sodium_init();

	int crypto_core_ed25519_from_uniform(byte[] result, byte[] encodedPoint);
	int crypto_core_ed25519_is_valid_point(byte[] encodedPoint);
	int crypto_scalarmult_ed25519_noclamp(byte[] result, byte[] encodedScalar, byte[] encodedBase);
	int crypto_scalarmult_ed25519_base_noclamp(byte[] result, byte[] encodedScalar);
	int crypto_core_ed25519_add(byte[] result, byte[] encodedA, byte[] encodedB);
	int crypto_core_ed25519_sub(byte[] result, byte[] encodedA, byte[] encodedB);
}
