package vss.commitment;

import vss.Constants;
import vss.commitment.constant.KateCommitmentScheme;
import vss.commitment.linear.FeldmanCommitmentScheme;
import vss.commitment.linear.ec.ECFeldmanCommitmentScheme;
import vss.commitment.linear.ec.c.CECFeldmanCommitmentScheme;
import vss.parameters.DHRFC5114Modp2048p256;
import vss.parameters.ECSecp256r1;

import java.math.BigInteger;

public class CommitmentSchemeFactory {

	public static CommitmentScheme createCommitmentScheme(String commitmentSchemeType,
	                                                      int threshold, BigInteger[] shareholders) {
		switch (commitmentSchemeType) {
			case Constants.VALUE_FELDMAN_SCHEME:
				return new FeldmanCommitmentScheme(
						DHRFC5114Modp2048p256.primeField,
						DHRFC5114Modp2048p256.generator,
						DHRFC5114Modp2048p256.subPrimeField
				);
			case Constants.VALUE_EC_FELDMAN_SCHEME:
				return new ECFeldmanCommitmentScheme(
						ECSecp256r1.primeField,
						ECSecp256r1.subPrimeField,
						ECSecp256r1.a,
						ECSecp256r1.b,
						ECSecp256r1.compressedGenerator
				);
			case Constants.VALUE_C_EC_FELDMAN_SCHEME:
				return new CECFeldmanCommitmentScheme();
			case Constants.VALUE_DL_KZG_SCHEME:
				return new KateCommitmentScheme(threshold, shareholders);
			default:
				throw new IllegalArgumentException("Unknown commitmentSchemeType " + commitmentSchemeType);
		}
	}
}
