package vss.commitment.constant.ped;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentSchemeType;
import vss.commitment.CommitmentType;
import vss.facade.SecretSharingException;
import vss.interpolation.LagrangeInterpolation;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class PedKZGCommitmentScheme implements CommitmentScheme {
	private final PedKZGRelicLibrary library;
	private final int scalarSize;
	private final int pointSize;
	private final BigInteger subPrimeField;
	private final BigInteger primeField;
	private final SecureRandom rndGenerator;
	private final int threshold;
	private final BigInteger[] shareholders;
	private final byte[] serializedShareholders;

	public PedKZGCommitmentScheme(int threshold, BigInteger[] shareholders) {
		this.threshold = threshold;
		this.shareholders = shareholders;
		this.library = PedKZGRelicLibrary.INSTANCE;
		this.rndGenerator = new SecureRandom("kzg".getBytes());

		// in production, derive the public SRS from a random secret alpha generated via MPC/trusted setup
		BigInteger alpha = new BigInteger("d0064469ce5c0401240f815ea2d6d3abb6d26d319e27f39dff0a5980157ebd69", 16);
		byte[] alphaBytes = alpha.toByteArray();

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
		return CommitmentSchemeType.PED_KZG_SCHEME;
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
		BigInteger blindingSecret = new BigInteger(subPrimeField.bitLength(), rndGenerator).mod(subPrimeField);
		Polynomial blindingPolynomial = new Polynomial(subPrimeField, threshold, blindingSecret, rndGenerator);
		BigInteger[] blindingCoefficients = blindingPolynomial.getCoefficients();

		byte[] serializedSecretCoefficients = flattenBigIntegerArray(coefficients);
		byte[] serializedBlindingCoefficients = flattenBigIntegerArray(blindingCoefficients);
		byte[] serializedAdditionalShareholders = flattenBigIntegerArray(additionalShareholders);

		byte[] commitment = new byte[pointSize];
		byte[] flattenedWitnesses = new byte[shareholders.length * pointSize];
		byte[] flattenedAdditionalWitnesses = new byte[nAdditionalShareholders * pointSize];

		int status = library.jna_commit_and_create_witnesses_ped(serializedSecretCoefficients,
				serializedBlindingCoefficients, serializedShareholders, shareholders.length,
				serializedAdditionalShareholders, nAdditionalShareholders, commitment,
				flattenedWitnesses, flattenedAdditionalWitnesses);
		if (status != 0) {
			throw new RuntimeException("Failed to create commitment and witnesses from KZG library, status: " + status);
		}

		byte[][] witnesses = unflattenPointArray(flattenedWitnesses, shareholders.length);
		TreeMap<Integer, byte[]> witnessMap = new TreeMap<>();
		TreeMap<Integer, byte[]> blindingSharesMap = new TreeMap<>();
		for (int i = 0; i < shareholders.length; i++) {
			BigInteger shareholder = shareholders[i];
			BigInteger blindingShare = blindingPolynomial.evaluateAt(shareholder);
			int shareholderHash = shareholder.hashCode();
			witnessMap.put(shareholderHash, witnesses[i]);
			blindingSharesMap.put(shareholderHash, serializeBigInteger(blindingShare));
		}
		if (nAdditionalShareholders > 0) {
			byte[][] additionalWitnesses = unflattenPointArray(flattenedAdditionalWitnesses, nAdditionalShareholders);
			for (int i = 0; i < nAdditionalShareholders; i++) {
				BigInteger additionalShareholder = additionalShareholders[i];
				BigInteger blindingShare = blindingPolynomial.evaluateAt(additionalShareholder);
				int additionalShareholderHash = additionalShareholder.hashCode();
				witnessMap.put(additionalShareholderHash, additionalWitnesses[i]);
				blindingSharesMap.put(additionalShareholderHash, serializeBigInteger(blindingShare));
			}
		}

		return new PedKZGCommitment(commitment, witnessMap, blindingSharesMap);
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
		byte[][] blindingShares = new byte[commitments.length][];
		for (int i = 0; i < commitments.length; i++) {
			if (commitments[i] instanceof PedKZGCommitment) {
				PedKZGCommitment pedersenCommitment = (PedKZGCommitment) commitments[i];
				commitmentsBytes[i] = pedersenCommitment.getCommitment();
				witnessesBytes[i] = pedersenCommitment.getWitness(x);
				blindingShares[i] = pedersenCommitment.getBlindingShare(x);
			} else {
				SharePedKZGCommitment sharePedKZGCommitment = (SharePedKZGCommitment) commitments[i];
				commitmentsBytes[i] = sharePedKZGCommitment.getCommitment();
				witnessesBytes[i] = sharePedKZGCommitment.getWitness();
				blindingShares[i] = sharePedKZGCommitment.getBlindingShare();
			}
		}
		byte[] flattenedCommitmentsBytes = flattenPointsByteArray(commitmentsBytes);
		byte[] flattenedWitnessesBytes = flattenPointsByteArray(witnessesBytes);
		byte[] flattenedBlindingShares = flattenScalarByteArray(blindingShares);
		int status = library.jna_verify_same_secret_evaluation_at_ped(xBytes, commitments.length,
				flattenedCommitmentsBytes, flattenedWitnessesBytes, flattenedBlindingShares);
		return status == 1;// status = 0 is false, status = 1 is true
	}

	@Override
	public boolean checkValidityWithoutPreComputation(Share share, Commitment commitment) {
		byte[] commitmentBytes;
		byte[] witnessBytes;
		byte[] blindingSharesBytes;
		if (commitment instanceof PedKZGCommitment) {
			PedKZGCommitment pedersenConstantCommitment = (PedKZGCommitment) commitment;
			commitmentBytes = pedersenConstantCommitment.getCommitment();
			witnessBytes = pedersenConstantCommitment.getWitness(share.getShareholder());
			blindingSharesBytes = pedersenConstantCommitment.getBlindingShare(share.getShareholder());
		} else {
			SharePedKZGCommitment sharePedersenCommitment = (SharePedKZGCommitment) commitment;
			commitmentBytes = sharePedersenCommitment.getCommitment();
			witnessBytes = sharePedersenCommitment.getWitness();
			blindingSharesBytes = sharePedersenCommitment.getBlindingShare();
		}
		byte[] shareholderBytes = serializeBigInteger(share.getShareholder());
		byte[] shareBytes = serializeBigInteger(share.getShare());
		int status = library.jna_verify_share_ped(shareholderBytes, shareBytes, blindingSharesBytes, commitmentBytes,
				witnessBytes);
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
				if (commitment instanceof PedKZGCommitment)
					firstType = CommitmentType.CONSTANT;
				else if (commitment instanceof SharePedKZGCommitment)
					firstType = CommitmentType.SHARE_COMMITMENT;
			} else {
				if (commitment instanceof PedKZGCommitment && !firstType.equals(CommitmentType.CONSTANT))
					return null;
				else if (commitment instanceof SharePedKZGCommitment && !firstType.equals(CommitmentType.SHARE_COMMITMENT))
					return null;
			}
		}
		return firstType;
	}

	private Commitment sumConstantCommitments(Commitment[] commitments) throws SecretSharingException {
		PedKZGCommitment[] constantCommitments = new PedKZGCommitment[commitments.length];
		Set<Integer> shareholders = new HashSet<>(((PedKZGCommitment)commitments[0]).getWitnesses().keySet());
		byte[][] commitmentsBytes = new byte[commitments.length][];

		for (int i = 0; i < commitments.length; i++) {
			PedKZGCommitment constantCommitment = (PedKZGCommitment)commitments[i];
			constantCommitments[i] = constantCommitment;
			Map<Integer, byte[]> witnesses = constantCommitment.getWitnesses();
			Map<Integer, byte[]> blindingShares = constantCommitment.getBlindingShares();

			if (shareholders.size() != witnesses.size()) {
				throw new SecretSharingException("Commitments contain witness from different shareholders");
			}

			if (shareholders.size() != blindingShares.size()) {
				throw new SecretSharingException("Commitments contain blindingShare from different shareholders");
			}

			for (Integer shareholderHash : witnesses.keySet()) {
				if (!shareholders.contains(shareholderHash)) {
					throw new SecretSharingException("Commitments contain witness from different shareholders");
				}
				if (!blindingShares.containsKey(shareholderHash)) {
					throw new SecretSharingException("Commitments contain blindingShare from different shareholders");
				}
			}

			commitmentsBytes[i] = constantCommitment.getCommitment();
		}

		Map<Integer, byte[][]> witnessToSum = new HashMap<>(shareholders.size());
		Map<Integer, byte[][]> blindingShareToSum = new HashMap<>(shareholders.size());
		for (Integer shareholder : shareholders) {
			byte[][] witnesses = new byte[constantCommitments.length][];
			byte[][] blindingShares = new byte[constantCommitments.length][];
			for (int i = 0; i < constantCommitments.length; i++) {
				witnesses[i] = constantCommitments[i].getWitness(shareholder);
				blindingShares[i] = constantCommitments[i].getBlindingShare(shareholder);
			}
			witnessToSum.put(shareholder, witnesses);
			blindingShareToSum.put(shareholder, blindingShares);
		}
		byte[] flattenedCommitmentsBytes = flattenPointsByteArray(commitmentsBytes);
		byte[] commitmentResult = new byte[pointSize];
		int status = library.jna_add_points(flattenedCommitmentsBytes, commitmentsBytes.length, commitmentResult);
		if  (status != 0) {
			throw new SecretSharingException("Failed to add commitments");
		}
		TreeMap<Integer, byte[]> witnessesResult = new TreeMap<>();
		TreeMap<Integer, byte[]> blindingSharesResult = new TreeMap<>();

		for (Map.Entry<Integer, byte[][]> entry : witnessToSum.entrySet()) {
			byte[] flattenedWitnessesBytes = flattenPointsByteArray(entry.getValue());
			byte[] witnessResult = new byte[pointSize];
			status = library.jna_add_points(flattenedWitnessesBytes, entry.getValue().length, witnessResult);
			if (status != 0) {
				throw new SecretSharingException("Failed to add witnesses");
			}
			witnessesResult.put(entry.getKey(), witnessResult);
		}

		for (Map.Entry<Integer, byte[][]> entry : blindingShareToSum.entrySet()) {
			BigInteger blindingShareResult = BigInteger.ZERO;
			for (byte[] blindingShareBytes : entry.getValue()) {
				BigInteger blindingShare = new BigInteger(1, blindingShareBytes);
				blindingShareResult = blindingShareResult.add(blindingShare).mod(subPrimeField);
			}
			byte[] blindingResult = serializeBigInteger(blindingShareResult);
			blindingSharesResult.put(entry.getKey(), blindingResult);
		}

		return new PedKZGCommitment(commitmentResult, witnessesResult, blindingSharesResult);
	}

	private Commitment sumShareCommitments(Commitment[] commitments) throws SecretSharingException {
		byte[][] commitmentsBytes = new byte[commitments.length][];
		byte[][] witnesses = new byte[commitments.length][];
		byte[][] blindingShares = new byte[commitments.length][];
		for (int i = 0; i < commitments.length; i++) {
			SharePedKZGCommitment shareCommitment = (SharePedKZGCommitment) commitments[i];
			witnesses[i] = shareCommitment.getWitness();
			commitmentsBytes[i] = shareCommitment.getCommitment();
			blindingShares[i] = shareCommitment.getBlindingShare();
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

		BigInteger blindingShareResult = BigInteger.ZERO;
		for (byte[] blindingShareBytes : blindingShares) {
			BigInteger blindingShare = new BigInteger(1, blindingShareBytes);
			blindingShareResult = blindingShareResult.add(blindingShare).mod(subPrimeField);
		}
		byte[] blindingResult = serializeBigInteger(blindingShareResult);

		return new SharePedKZGCommitment(commitmentResult, witnessResult, blindingResult);
	}


	@Override
	public Commitment subtractCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
		if (!c1.getCommitmentType().equals(c2.getCommitmentType()))
			throw new SecretSharingException("Commitments must have same type");
		if (c1.getCommitmentType().equals(CommitmentType.CONSTANT))
			return subtractConstantCommitments(c1, c2);
		if (c2.getCommitmentType().equals(CommitmentType.SHARE_COMMITMENT))
			return subtractShareCommitments(c1, c2);
		return null;
	}

	private Commitment subtractConstantCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
		PedKZGCommitment constantC1 = (PedKZGCommitment) c1;
		PedKZGCommitment constantC2 = (PedKZGCommitment) c2;
		Set<Integer> witnessShareholders = new HashSet<>(constantC1.getWitnesses().keySet());
		Set<Integer> blindingShareholders = new HashSet<>(constantC1.getBlindingShares().keySet());

		if (witnessShareholders.size() != constantC2.getWitnesses().size()) {
			throw new SecretSharingException("Commitments contain witness from different shareholders");
		}

		if (blindingShareholders.size() != constantC2.getBlindingShares().size()) {
			throw new SecretSharingException("Commitments contain blindingShare from different shareholders");
		}

		for (Integer shareholderHash : constantC2.getWitnesses().keySet()) {
			if (!witnessShareholders.contains(shareholderHash)) {
				throw new SecretSharingException("Commitments contain witness from different shareholders");
			}
		}

		for (Integer shareholderHash : constantC2.getBlindingShares().keySet()) {
			if (!blindingShareholders.contains(shareholderHash)) {
				throw new SecretSharingException("Commitments contain blindingShare from different shareholders");
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

		TreeMap<Integer, byte[]> blindingSharesResult = new TreeMap<>();
		Iterator<Map.Entry<Integer, byte[]>> b1 = constantC1.getBlindingShares().entrySet().iterator();
		Iterator<Map.Entry<Integer, byte[]>> b2 = constantC2.getBlindingShares().entrySet().iterator();

		while (b1.hasNext()) {
			Map.Entry<Integer, byte[]> e1 = b1.next();
			Map.Entry<Integer, byte[]> e2 = b2.next();
			BigInteger blindingShare1 = new BigInteger(1, e1.getValue());
			BigInteger blindingShare2 = new BigInteger(1, e2.getValue());
			BigInteger blindingShareResult = blindingShare1.subtract(blindingShare2).mod(subPrimeField);
			blindingSharesResult.put(e1.getKey(), serializeBigInteger(blindingShareResult));
		}

		return new PedKZGCommitment(commitmentResult, w, blindingSharesResult);
	}

	private Commitment subtractShareCommitments(Commitment c1, Commitment c2) {
		SharePedKZGCommitment s1 = (SharePedKZGCommitment) c1;
		SharePedKZGCommitment s2 = (SharePedKZGCommitment) c2;

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

		BigInteger blindingShare1 = new BigInteger(1, s1.getBlindingShare());
		BigInteger blindingShare2 = new BigInteger(1, s2.getBlindingShare());
		BigInteger blindingShareResult = blindingShare1.subtract(blindingShare2).mod(subPrimeField);
		return new SharePedKZGCommitment(commitmentResult, witnessResult, serializeBigInteger(blindingShareResult));
	}

	@Override
	public Commitment addConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		if (commitment instanceof PedKZGCommitment) {
			PedKZGCommitment pedersenConstantCommitment = (PedKZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant);
			byte[] resultCommitment = new byte[pointSize];
			int status = library.jna_add_constant_to_point(pedersenConstantCommitment.getCommitment(), constantBytes, resultCommitment);
			if (status != 0) {
				throw new SecretSharingException("Failed to add constant to commitment");
			}
			return new PedKZGCommitment(resultCommitment, pedersenConstantCommitment.getWitnesses(),
					pedersenConstantCommitment.getBlindingShares());
		} else if (commitment instanceof SharePedKZGCommitment) {
			SharePedKZGCommitment shareCommitment = (SharePedKZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant);
			byte[] resultCommitment = new byte[pointSize];
			int status = library.jna_add_constant_to_point(shareCommitment.getCommitment(), constantBytes, resultCommitment);
			if (status != 0) {
				throw new SecretSharingException("Failed to add constant to commitment");
			}
			return new SharePedKZGCommitment(resultCommitment, shareCommitment.getWitness(),
					shareCommitment.getBlindingShare());
		} else {
			throw new SecretSharingException("Unsupported commitment type");
		}
	}

	@Override
	public Commitment subtractConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		constant = constant.negate().mod(subPrimeField);
		if (commitment instanceof PedKZGCommitment) {
			PedKZGCommitment pedersenConstantCommitment = (PedKZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant);
			byte[] resultCommitment = new byte[pointSize];
			int status = library.jna_add_constant_to_point(pedersenConstantCommitment.getCommitment(), constantBytes, resultCommitment);
			if (status != 0) {
				throw new SecretSharingException("Failed to add constant to commitment");
			}
			return new PedKZGCommitment(resultCommitment, pedersenConstantCommitment.getWitnesses(),
					pedersenConstantCommitment.getBlindingShares());
		} else if (commitment instanceof SharePedKZGCommitment) {
			SharePedKZGCommitment shareCommitment = (SharePedKZGCommitment) commitment;
			byte[] constantBytes = serializeBigInteger(constant);
			byte[] resultCommitment = new byte[pointSize];
			int status = library.jna_add_constant_to_point(shareCommitment.getCommitment(), constantBytes, resultCommitment);
			if (status != 0) {
				throw new SecretSharingException("Failed to add constant to commitment");
			}
			return new SharePedKZGCommitment(resultCommitment, shareCommitment.getWitness(),
					shareCommitment.getBlindingShare());
		} else {
			throw new SecretSharingException("Unsupported commitment type");
		}
	}

	@Override
	public Commitment multiplyByConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		if (commitment instanceof PedKZGCommitment) {
			PedKZGCommitment kzgCommitment = (PedKZGCommitment) commitment;
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
			TreeMap<Integer, byte[]> blindingSharesResult = new TreeMap<>();
			for (Map.Entry<Integer, byte[]> entry : kzgCommitment.getBlindingShares().entrySet()) {
				BigInteger blindingShare = new BigInteger(1, entry.getValue());
				BigInteger blindingShareResult = blindingShare.multiply(constant).mod(subPrimeField);
				blindingSharesResult.put(entry.getKey(), serializeBigInteger(blindingShareResult));
			}
			return new PedKZGCommitment(commitmentResult, witnessesResult, blindingSharesResult);
		} else if (commitment instanceof SharePedKZGCommitment) {
			SharePedKZGCommitment shareCommitment = (SharePedKZGCommitment) commitment;
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
			BigInteger blindingShare = new BigInteger(1, shareCommitment.getBlindingShare());
			BigInteger blindingShareResult = blindingShare.multiply(constant).mod(subPrimeField);
			return new SharePedKZGCommitment(commitmentResult, witnessResult,
					serializeBigInteger(blindingShareResult));
		} else {
			throw new SecretSharingException("Unsupported commitment type");
		}
	}

	@Override
	public Commitment extractCommitment(BigInteger shareholder, Commitment commitment) {
		PedKZGCommitment pedersenConstantCommitment = (PedKZGCommitment) commitment;
		byte[] witness = pedersenConstantCommitment.getWitness(shareholder);
		byte[] blindingShare = pedersenConstantCommitment.getBlindingShare(shareholder);
		if (witness == null || blindingShare == null) {
			throw new IllegalArgumentException("Shareholder not found in the commitment");
		}

		return new SharePedKZGCommitment(pedersenConstantCommitment.getCommitment(),
				witness, blindingShare);
	}

	@Override
	public Commitment combineCommitments(Map<BigInteger, Commitment> commitments) {
		byte[] resultCommitment = null;
		TreeMap<Integer, byte[]> resultWitnesses = new TreeMap<>();
		TreeMap<Integer, byte[]> resultBlindingShares = new TreeMap<>();
		for (Map.Entry<BigInteger, Commitment> entry : commitments.entrySet()) {
			SharePedKZGCommitment shareCommitment = (SharePedKZGCommitment) entry.getValue();
			if (resultCommitment == null) {
				resultCommitment = shareCommitment.getCommitment();
			}
			resultWitnesses.put(entry.getKey().hashCode(), shareCommitment.getWitness());
			resultBlindingShares.put(entry.getKey().hashCode(), shareCommitment.getBlindingShare());
		}
		return new PedKZGCommitment(resultCommitment, resultWitnesses, resultBlindingShares);
	}

	@Override
	public Commitment recoverCommitment(BigInteger newShareholder, Map<BigInteger, Commitment> commitments) throws SecretSharingException {
		byte[] commitment = null;
		byte[][] witnesses = new byte[commitments.size()][];
		BigInteger[] shareholders = new BigInteger[commitments.size()];
		Share[] blindingShares = new Share[commitments.size()];
		int i = 0;
		for (Map.Entry<BigInteger, Commitment> entry : commitments.entrySet()) {
			SharePedKZGCommitment shareCommitment = (SharePedKZGCommitment) entry.getValue();
			if (commitment == null)
				commitment = shareCommitment.getCommitment();
			witnesses[i] = shareCommitment.getWitness();
			shareholders[i] = entry.getKey();
			blindingShares[i] = new Share(entry.getKey(), new BigInteger(1, shareCommitment.getBlindingShare()));
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

		BigInteger recoveredBlindedShare = (new LagrangeInterpolation(subPrimeField)).interpolateAt(newShareholder, blindingShares);
		byte[] recoveredBlindingShareBytes = serializeBigInteger(recoveredBlindedShare);

		return new SharePedKZGCommitment(commitment, recoveredWitness, recoveredBlindingShareBytes);
	}

	@Override
	public Commitment readCommitment(ObjectInput in) throws IOException, ClassNotFoundException {
		CommitmentType commitmentType = CommitmentType.getType(in.read());
		Commitment result = null;
		switch (commitmentType) {
			case CONSTANT:
				result = new PedKZGCommitment();
				break;
			case SHARE_COMMITMENT:
				result = new SharePedKZGCommitment();
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

	private byte[] flattenScalarByteArray(byte[][] scalarsBytes) {
		if (scalarsBytes == null) {
			return new byte[0];
		}
		byte[] result = new byte[scalarsBytes.length * scalarSize];
		for (int i = 0; i < scalarsBytes.length; i++) {
			byte[] bytes = scalarsBytes[i];
			System.arraycopy(bytes, 0, result, i * scalarSize + scalarSize - bytes.length, bytes.length);
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
