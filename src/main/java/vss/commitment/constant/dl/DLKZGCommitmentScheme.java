package vss.commitment.constant.dl;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentSchemeType;
import vss.commitment.CommitmentType;
import vss.commitment.constant.KZGCommitment;
import vss.commitment.constant.ShareKZGCommitment;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.*;

public class DLKZGCommitmentScheme implements CommitmentScheme {
	private final DLKZGRelicLibrary library;
	private final int scalarSize;
	private final int pointSize;
	private final BigInteger subPrimeField;
	private final BigInteger primeField;
	private final BigInteger[] shareholders;
	private final byte[] serializedShareholders;

	public DLKZGCommitmentScheme(int threshold, BigInteger[] shareholders) {
		this.shareholders = shareholders;
		this.library = DLKZGRelicLibrary.INSTANCE;

		// in production, derive the public SRS from a random secret alpha generated via MPC/trusted setup
		BigInteger alpha = new BigInteger("d0064469ce5c0401240f815ea2d6d3abb6d26d319e27f39dff0a5980157ebd69", 16);
		byte[] alphaBytes = alpha.toByteArray();
		System.out.println();

		this.library.jna_initialize(threshold, alphaBytes, alphaBytes.length);

		this.scalarSize = library.jna_scalar_size();
		int primeFieldSize = library.jna_prime_size();
		this.pointSize = library.jna_g1_size();

		byte[] subPrimeFieldBytes = new byte[scalarSize];
		int status = library.jna_get_sub_prime_field(subPrimeFieldBytes);
		if (status != 0) {
			throw new RuntimeException("Failed to get sub-prime field from KZG library, status: " + status);
		}
		this.subPrimeField = new BigInteger(1, subPrimeFieldBytes);

		byte[] primeFieldBytes = new byte[primeFieldSize];
		status = library.jna_get_prime_field(primeFieldBytes);
		if (status != 0) {
			throw new RuntimeException("Failed to get prime field from KZG library, status: " + status);
		}
		this.primeField = new BigInteger(1, primeFieldBytes);

		this.serializedShareholders = flattenBigIntegerArray(shareholders);
	}

	@Override
	public CommitmentSchemeType getCommitmentSchemeType() {
		return CommitmentSchemeType.DL_KZG_SCHEME;
	}

	@Override
	public BigInteger getPrimeFieldOrder() {
		return primeField;
	}

	@Override
	public BigInteger getSubPrimeFieldOrder() {
		return subPrimeField;
	}

	@Override
	public Commitment generateCommitments(Polynomial polynomial, BigInteger... additionalShareholders) {
		int nAdditionalShareholders = additionalShareholders == null || additionalShareholders.length == 0
				? 0 : additionalShareholders.length;
		BigInteger[] coefficients = polynomial.getCoefficients();

		byte[] serializedSecretCoefficients = flattenBigIntegerArray(coefficients);
		byte[] serializedAdditionalShareholders = flattenBigIntegerArray(additionalShareholders);

		byte[] commitment = new byte[pointSize];
		byte[] flattenedWitnesses = new byte[shareholders.length * pointSize];
		byte[] flattenedAdditionalWitnesses = new byte[nAdditionalShareholders * pointSize];

		int status = library.jna_commit_and_create_witnesses_dl(serializedSecretCoefficients,
				serializedShareholders, shareholders.length,
				serializedAdditionalShareholders, nAdditionalShareholders, commitment,
				flattenedWitnesses, flattenedAdditionalWitnesses);
		if (status != 0) {
			throw new RuntimeException("Failed to create commitment and witnesses from KZG library, status: " + status);
		}

		byte[][] witnesses = unflattenPointArray(flattenedWitnesses, shareholders.length);
		TreeMap<Integer, byte[]> witnessMap = new TreeMap<>();
		for (int i = 0; i < shareholders.length; i++) {
			BigInteger shareholder = shareholders[i];
			int shareholderHash = shareholder.hashCode();
			witnessMap.put(shareholderHash, witnesses[i]);
		}
		if (nAdditionalShareholders > 0) {
			byte[][] additionalWitnesses = unflattenPointArray(flattenedAdditionalWitnesses, nAdditionalShareholders);
			for (int i = 0; i < nAdditionalShareholders; i++) {
				BigInteger additionalShareholder = additionalShareholders[i];
				int additionalShareholderHash = additionalShareholder.hashCode();
				witnessMap.put(additionalShareholderHash, additionalWitnesses[i]);
			}
		}

		return new KZGCommitment(commitment, witnessMap);
	}

	@Override
	public void addShareholder(BigInteger shareholder) {
		throw new UnsupportedOperationException("TODO");
	}

	@Override
	public void removeShareholder(BigInteger shareholder) {
		throw new UnsupportedOperationException("TODO");
	}

	@Override
	public boolean checkValidityOfPolynomialsProperty(BigInteger x, Commitment... commitments) {
		byte[] xBytes = serializeBigInteger(x);
		byte[][] commitmentsBytes = new byte[commitments.length][];
		byte[][] witnessesBytes = new byte[commitments.length][];
		for (int i = 0; i < commitments.length; i++) {
			if (commitments[i] instanceof KZGCommitment) {
				KZGCommitment kzgCommitment = (KZGCommitment) commitments[i];
				commitmentsBytes[i] = kzgCommitment.getCommitment();
				witnessesBytes[i] = kzgCommitment.getWitness(x);
			} else {
				ShareKZGCommitment shareKZGCommitment = (ShareKZGCommitment) commitments[i];
				commitmentsBytes[i] = shareKZGCommitment.getCommitment();
				witnessesBytes[i] = shareKZGCommitment.getWitness();
			}
		}
		byte[] flattenedCommitmentsBytes = flattenPointsByteArray(commitmentsBytes);
		byte[] flattenedWitnessesBytes = flattenPointsByteArray(witnessesBytes);
		int status = library.jna_verify_same_secret_evaluation_at_dl(xBytes, commitments.length,
				flattenedCommitmentsBytes, flattenedWitnessesBytes);
		return status == 1;// status = 0 is false, status = 1 is true
	}

	@Override
	public boolean checkValidityWithoutPreComputation(Share share, Commitment commitment) {
		byte[] commitmentBytes;
		byte[] witnessBytes;
		if (commitment instanceof KZGCommitment) {
			KZGCommitment kzgCommitment = (KZGCommitment) commitment;
			commitmentBytes = kzgCommitment.getCommitment();
			witnessBytes = kzgCommitment.getWitness(share.getShareholder());
		} else {
			ShareKZGCommitment shareKZGCommitment = (ShareKZGCommitment) commitment;
			commitmentBytes = shareKZGCommitment.getCommitment();
			witnessBytes = shareKZGCommitment.getWitness();
		}
		byte[] shareholderBytes = serializeBigInteger(share.getShareholder());
		byte[] shareBytes = serializeBigInteger(share.getShare());
		int status = library.jna_verify_share_dl(shareholderBytes, shareBytes, commitmentBytes, witnessBytes);
		return status == 1;// status = 0 is false, status = 1 is true
	}

	@Override
	public Commitment sumCommitments(Commitment... commitments) throws SecretSharingException {
		CommitmentType type = getCommitmentType(commitments);
		if (type == null)
			throw new SecretSharingException("Commitments must have same type");
		if (type == CommitmentType.CONSTANT)
			return sumConstantCommitments(commitments);
		else if (type == CommitmentType.SHARE_COMMITMENT)
			return sumShareCommitments(commitments);

		return null;
	}

	private CommitmentType getCommitmentType(Commitment[] commitments) {
		CommitmentType firstType = null;
		for (Commitment commitment : commitments) {
			if (firstType == null) {
				if (commitment instanceof KZGCommitment)
					firstType = CommitmentType.CONSTANT;
				else if (commitment instanceof ShareKZGCommitment)
					firstType = CommitmentType.SHARE_COMMITMENT;
			} else {
				if (commitment instanceof KZGCommitment && !firstType.equals(CommitmentType.CONSTANT))
					return null;
				else if (commitment instanceof ShareKZGCommitment && !firstType.equals(CommitmentType.SHARE_COMMITMENT))
					return null;
			}
		}
		return firstType;
	}

	private Commitment sumConstantCommitments(Commitment[] commitments) throws SecretSharingException {
		KZGCommitment[] constantCommitments = new KZGCommitment[commitments.length];
		Set<Integer> shareholders = new HashSet<>(((KZGCommitment)commitments[0]).getWitnesses().keySet());
		byte[][] commitmentsBytes = new byte[commitments.length][];

		for (int i = 0; i < commitments.length; i++) {
			KZGCommitment constantCommitment = (KZGCommitment)commitments[i];
			constantCommitments[i] = constantCommitment;
			Map<Integer, byte[]> witnesses = constantCommitment.getWitnesses();

			if (shareholders.size() != witnesses.size()) {
				throw new SecretSharingException("Commitments contain witness from different shareholders");
			}

			for (Integer shareholderHash : witnesses.keySet()) {
				if (!shareholders.contains(shareholderHash)) {
					throw new SecretSharingException("Commitments contain witness from different shareholders");
				}
			}

			commitmentsBytes[i] = constantCommitment.getCommitment();
		}

		Map<Integer, byte[][]> witnessToSum = new HashMap<>(shareholders.size());
		for (Integer shareholder : shareholders) {
			byte[][] witnesses = new byte[constantCommitments.length][];
			for (int i = 0; i < constantCommitments.length; i++) {
				witnesses[i] = constantCommitments[i].getWitness(shareholder);
			}
			witnessToSum.put(shareholder, witnesses);
		}
		byte[] flattenedCommitmentsBytes = flattenPointsByteArray(commitmentsBytes);
		byte[] commitmentResult = new byte[pointSize];
		int status = library.jna_add_points(flattenedCommitmentsBytes, commitmentsBytes.length, commitmentResult);
		if  (status != 0) {
			throw new SecretSharingException("Failed to add commitments");
		}
		TreeMap<Integer, byte[]> witnessesResult = new TreeMap<>();

		for (Map.Entry<Integer, byte[][]> entry : witnessToSum.entrySet()) {
			byte[] flattenedWitnessesBytes = flattenPointsByteArray(entry.getValue());
			byte[] witnessResult = new byte[pointSize];
			status = library.jna_add_points(flattenedWitnessesBytes, entry.getValue().length, witnessResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to add witnesses");
			}
			witnessesResult.put(entry.getKey(), witnessResult);
		}

		return new KZGCommitment(commitmentResult, witnessesResult);
	}

	private Commitment sumShareCommitments(Commitment[] commitments) throws SecretSharingException {
		byte[][] commitmentsBytes = new byte[commitments.length][];
		byte[][] witnesses = new byte[commitments.length][];
		for (int i = 0; i < commitments.length; i++) {
			ShareKZGCommitment shareCommitment = (ShareKZGCommitment) commitments[i];
			witnesses[i] = shareCommitment.getWitness();
			commitmentsBytes[i] = shareCommitment.getCommitment();
		}

		byte[] flattenedCommitmentsBytes = flattenPointsByteArray(commitmentsBytes);
		byte[] commitmentResult = new byte[pointSize];
		int status = library.jna_add_points(flattenedCommitmentsBytes, commitmentsBytes.length, commitmentResult);
		if  (status != 0) {
			throw new SecretSharingException("Failed to add commitments");
		}
		byte[] flattenedWitnessesBytes = flattenPointsByteArray(witnesses);
		byte[] witnessResult = new byte[pointSize];
		status = library.jna_add_points(flattenedWitnessesBytes, witnesses.length, witnessResult);
		if (status != 0) {
			throw new SecretSharingException("Failed to add witnesses");
		}

		return new ShareKZGCommitment(commitmentResult, witnessResult);
	}


	@Override
	public Commitment subtractCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
		if (!c1.getCommitmentType().equals(c2.getCommitmentType()))
			throw new SecretSharingException("Commitments must have same type (c1: " + c1.getCommitmentType() + ", c2: " + c2.getCommitmentType() + ")");
		if (c1.getCommitmentType().equals(CommitmentType.CONSTANT))
			return subtractConstantCommitments(c1, c2);
		if (c2.getCommitmentType().equals(CommitmentType.SHARE_COMMITMENT))
			return subtractShareCommitments(c1, c2);
		return null;
	}

	private Commitment subtractConstantCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
		KZGCommitment constantC1 = (KZGCommitment) c1;
		KZGCommitment constantC2 = (KZGCommitment) c2;
		Set<Integer> shareholders = new HashSet<>(constantC1.getWitnesses().keySet());

		if (shareholders.size() != constantC2.getWitnesses().size()) {
			throw new SecretSharingException("Commitments contain witness from different shareholders");
		}

		for (Integer shareholderHash : constantC2.getWitnesses().keySet()) {
			if (!shareholders.contains(shareholderHash)) {
				throw new SecretSharingException("Commitments contain witness from different shareholders");
			}
		}

		byte[] commitmentResult = new byte[pointSize];
		int status = library.jna_subtract_points(constantC1.getCommitment(), constantC2.getCommitment(), commitmentResult);
		if (status != 0) {
			throw new SecretSharingException("Failed to subtract commitments");
		}

		TreeMap<Integer, byte[]> w = new TreeMap<>();
		Iterator<Map.Entry<Integer, byte[]>> i1 = constantC1.getWitnesses().entrySet().iterator();
		Iterator<Map.Entry<Integer, byte[]>> i2 = constantC2.getWitnesses().entrySet().iterator();

		while (i1.hasNext()) {
			Map.Entry<Integer, byte[]> e1 = i1.next();
			Map.Entry<Integer, byte[]> e2 = i2.next();
			byte[] witnessResult = new byte[pointSize];
			status = library.jna_subtract_points(e1.getValue(), e2.getValue(), witnessResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to subtract witnesses");
			}
			w.put(e1.getKey(), witnessResult);
		}

		return new KZGCommitment(commitmentResult, w);
	}

	private Commitment subtractShareCommitments(Commitment c1, Commitment c2) {
		ShareKZGCommitment s1 = (ShareKZGCommitment) c1;
		ShareKZGCommitment s2 = (ShareKZGCommitment) c2;

		byte[] commitmentResult = new byte[pointSize];
		int status = library.jna_subtract_points(s1.getCommitment(), s2.getCommitment(), commitmentResult);
		if (status != 0) {
			throw new RuntimeException("Failed to subtract commitments");
		}

		byte[] witnessResult = new byte[pointSize];
		status = library.jna_subtract_points(s1.getWitness(), s2.getWitness(), witnessResult);
		if (status != 0) {
			throw new RuntimeException("Failed to subtract witnesses");
		}
		return new ShareKZGCommitment(commitmentResult, witnessResult);
	}

	@Override
	public Commitment addConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		if (commitment instanceof KZGCommitment) {
			KZGCommitment kzgCommitment = (KZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant);
			byte[] commitmentResult = new byte[pointSize];
			int status = library.jna_add_constant_to_point(kzgCommitment.getCommitment(), constantBytes, commitmentResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to add constant to commitment");
			}
			return new KZGCommitment(commitmentResult, kzgCommitment.getWitnesses());
		} else if (commitment instanceof ShareKZGCommitment) {
			ShareKZGCommitment shareKZGCommitment = (ShareKZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant);
			byte[] commitmentResult = new byte[pointSize];
			int status = library.jna_add_constant_to_point(shareKZGCommitment.getCommitment(), constantBytes, commitmentResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to add constant to commitment");
			}
			return new ShareKZGCommitment(commitmentResult, shareKZGCommitment.getWitness());
		} else {
			throw new SecretSharingException("Unsupported commitment type");
		}
	}

	@Override
	public Commitment subtractConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		constant = constant.negate().mod(subPrimeField);
		if (commitment instanceof KZGCommitment) {
			KZGCommitment kzgCommitment = (KZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant);
			byte[] commitmentResult = new byte[pointSize];
			int status = library.jna_add_constant_to_point(kzgCommitment.getCommitment(), constantBytes, commitmentResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to add constant to commitment");
			}
			return new KZGCommitment(commitmentResult, kzgCommitment.getWitnesses());
		} else if (commitment instanceof ShareKZGCommitment) {
			ShareKZGCommitment shareKZGCommitment = (ShareKZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant);
			byte[] commitmentResult = new byte[pointSize];
			int status = library.jna_add_constant_to_point(shareKZGCommitment.getCommitment(), constantBytes, commitmentResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to add constant to commitment");
			}
			return new ShareKZGCommitment(commitmentResult, shareKZGCommitment.getWitness());
		} else {
			throw new SecretSharingException("Unsupported commitment type");
		}
	}

	@Override
	public Commitment multiplyByConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		if (commitment instanceof KZGCommitment) {
			KZGCommitment kzgCommitment = (KZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant.mod(subPrimeField));
			byte[] commitmentBytes = kzgCommitment.getCommitment();
			int[] shareholdersHashes = new int[kzgCommitment.getWitnesses().size()];
			byte[][] unflattenedWitnesses = new byte[kzgCommitment.getWitnesses().size()][];
			int index = 0;
			for (Map.Entry<Integer, byte[]> entry : kzgCommitment.getWitnesses().entrySet()) {
				shareholdersHashes[index] = entry.getKey();
				unflattenedWitnesses[index] = entry.getValue();
				index++;
			}
			byte[] flattenedWitnesses = flattenPointsByteArray(unflattenedWitnesses);

			byte[] commitmentResult = new byte[pointSize];
			byte[] flattenedWitnessesResult = new byte[kzgCommitment.getWitnesses().size() * pointSize];
			int status = library.jna_multiply_commitment_by_constant(commitmentBytes,
					kzgCommitment.getWitnesses().size(), flattenedWitnesses, constantBytes,
					commitmentResult, flattenedWitnessesResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to multiply commitment by constant");
			}

			byte[][] witnessesResultArray = unflattenPointArray(flattenedWitnessesResult, kzgCommitment.getWitnesses().size());
			TreeMap<Integer, byte[]> witnessesResult = new TreeMap<>();
			for (int i = 0; i < shareholdersHashes.length; i++) {
				witnessesResult.put(shareholdersHashes[i], witnessesResultArray[i]);
			}
			return new KZGCommitment(commitmentResult, witnessesResult);
		} else if (commitment instanceof ShareKZGCommitment) {
			ShareKZGCommitment shareCommitment = (ShareKZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant.mod(subPrimeField));
			byte[] commitmentBytes = shareCommitment.getCommitment();
			byte[] witnessBytes = shareCommitment.getWitness();

			byte[] commitmentResult = new byte[pointSize];
			byte[] witnessResult = new byte[pointSize];
			int status = library.jna_multiply_commitment_by_constant(commitmentBytes, 1, witnessBytes,
					constantBytes, commitmentResult, witnessResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to multiply commitment by constant");
			}

			return new ShareKZGCommitment(commitmentResult, witnessResult);
		} else {
			throw new SecretSharingException("Unsupported commitment type");
		}
	}

	@Override
	public Commitment extractCommitment(BigInteger shareholder, Commitment commitment) {
		KZGCommitment kzgCommitment = (KZGCommitment) commitment;
		byte[] witness = kzgCommitment.getWitness(shareholder.hashCode());
		if (witness == null) {
			throw new IllegalArgumentException("No witness found for shareholder: " + shareholder);
		}
		return new ShareKZGCommitment(kzgCommitment.getCommitment(), witness);
	}

	@Override
	public Commitment combineCommitments(Map<BigInteger, Commitment> commitments) {
		byte[] resultCommitment = null;
		TreeMap<Integer, byte[]> resultWitnesses = new TreeMap<>();
		for (Map.Entry<BigInteger, Commitment> entry : commitments.entrySet()) {
			ShareKZGCommitment shareCommitment = (ShareKZGCommitment)entry.getValue();
			if (resultCommitment == null)
				resultCommitment = shareCommitment.getCommitment();
			resultWitnesses.put(entry.getKey().hashCode(),
					shareCommitment.getWitness());
		}
		return new KZGCommitment(resultCommitment, resultWitnesses);
	}

	@Override
	public Commitment recoverCommitment(BigInteger newShareholder, Map<BigInteger, Commitment> commitments) throws SecretSharingException {
		byte[] commitment = null;
		byte[][] witnesses = new byte[commitments.size()][];
		BigInteger[] shareholders = new BigInteger[commitments.size()];
		int i = 0;
		for (Map.Entry<BigInteger, Commitment> entry : commitments.entrySet()) {
			ShareKZGCommitment shareCommitment = (ShareKZGCommitment) entry.getValue();
			if (commitment == null)
				commitment = shareCommitment.getCommitment();
			witnesses[i] = shareCommitment.getWitness();
			shareholders[i] = entry.getKey();
			i++;
		}

		byte[] flattenedWitnesses = flattenPointsByteArray(witnesses);
		byte[] flattenedShareholders = flattenBigIntegerArray(shareholders);
		byte[] recoveringShareholder = serializeBigInteger(newShareholder);
		byte[] recoveredWitness = new byte[pointSize];

		int status = library.jna_recover_witness(recoveringShareholder, commitments.size(), flattenedShareholders,
				flattenedWitnesses, recoveredWitness);
		if (status != 0) {
			throw new SecretSharingException("Failed to recover witness for shareholder: " + newShareholder);
		}
		return new ShareKZGCommitment(commitment, recoveredWitness);
	}

	@Override
	public Commitment readCommitment(ObjectInput in) throws IOException, ClassNotFoundException {
		CommitmentType commitmentType = CommitmentType.getType(in.read());
		Commitment result = null;
		switch (commitmentType) {
			case CONSTANT:
				result = new KZGCommitment();
				break;
			case SHARE_COMMITMENT:
				result = new ShareKZGCommitment();
				break;
		}
		if (result == null)
			return null;
		result.readExternal(in);
		return result;
	}

	@Override
	public void writeCommitment(Commitment commitment, ObjectOutput out) throws IOException {
		out.write(commitment.getCommitmentType().ordinal());
		commitment.writeExternal(out);
	}

	private byte[] flattenBigIntegerArray(BigInteger[] array) {
		if (array == null) {
			return new byte[0];
		}
		byte[] result = new byte[array.length * scalarSize];
		for (int i = 0; i < array.length; i++) {
			byte[] bytes = array[i].toByteArray();
			System.arraycopy(bytes, 0, result, i * scalarSize + scalarSize - bytes.length, bytes.length);
		}
		return result;
	}

	private byte[] flattenPointsByteArray(byte[][] commitmentsBytes) {
		if (commitmentsBytes == null) {
			return new byte[0];
		}
		byte[] result = new byte[commitmentsBytes.length * pointSize];
		for (int i = 0; i < commitmentsBytes.length; i++) {
			byte[] bytes = commitmentsBytes[i];
			System.arraycopy(bytes, 0, result, i * pointSize + pointSize - bytes.length, bytes.length);
		}
		return result;
	}

	private byte[][] unflattenPointArray(byte[] array, int numberOfPoints) {
		byte[][] result = new byte[numberOfPoints][pointSize];
		for (int i = 0; i < numberOfPoints; i++) {
			System.arraycopy(array, i * pointSize, result[i], 0, pointSize);
		}
		return result;
	}

	private byte[] serializeBigInteger(BigInteger value) {
		byte[] bytes = value.toByteArray();
		if (bytes.length != scalarSize) {
			byte[] fixedSizeBytes = new byte[scalarSize];
			System.arraycopy(bytes, 0, fixedSizeBytes, scalarSize - bytes.length, bytes.length);
			bytes = fixedSizeBytes;
		}
		return bytes;
	}
}
