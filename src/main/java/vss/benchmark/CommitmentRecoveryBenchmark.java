package vss.benchmark;

import org.bouncycastle.math.ec.ECPoint;
import vss.Constants;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.constant.ShareKZGCommitment;
import vss.commitment.linear.LinearCommitments;
import vss.commitment.linear.ec.ECLinearCommitment;
import vss.commitment.linear.ec.c.RawLinearCommitment;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.polynomial.Polynomial;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/**
 * @author Robin
 */
public class CommitmentRecoveryBenchmark {
	private static SecureRandom rndGenerator;
	private static int threshold;
	private static int n;
	private static BigInteger[] shareholders;

	public static void main(String[] args) throws SecretSharingException {
		if (args.length != 4) {
			System.out.println("USAGE: ... vss.benchmark.CommitmentRecoveryBenchmark " +
					"<threshold> " +
					"<min number of faulty shareholders> <max number of faulty shareholders> " +
					"<commitment scheme type: linear|ec_linear|c_ec_linear|dl_kzg|ped_kzg>");
			System.exit(-1);
		}

		threshold = Integer.parseInt(args[0]);
		n = 3 * threshold + 1;
		int minFaultyCommitments = Integer.parseInt(args[1]);
		int maxFaultyCommitments = Integer.parseInt(args[2]);
		String commitmentSchemeType = args[3];

		if (minFaultyCommitments < 0 || minFaultyCommitments > threshold || minFaultyCommitments > maxFaultyCommitments)
			throw new IllegalArgumentException("min number of faulty shareholders is out of range");

		if (maxFaultyCommitments > threshold)
			throw new IllegalArgumentException("max number of faulty shareholders is out of range");

		System.out.println("t: " + threshold);
		System.out.println("n: " + n);
		System.out.println("commitment scheme type: " + commitmentSchemeType);
		System.out.println();


		rndGenerator = new SecureRandom("ola".getBytes());
		shareholders = new BigInteger[n];
		for (int i = 0; i < n; i++) {
			shareholders[i] = BigInteger.valueOf(i + 1);
		}

		Properties properties = new Properties();
		properties.put(Constants.TAG_THRESHOLD, String.valueOf(threshold));
		properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, "AES");
		properties.put(Constants.TAG_COMMITMENT_SCHEME, commitmentSchemeType);

		VSSFacade vssFacade = new VSSFacade(properties, shareholders);
		runTests(vssFacade, minFaultyCommitments, maxFaultyCommitments);
	}

	private static void runTests(VSSFacade vss, int minFaultyC, int maxFaultyC) {
		BigInteger field = vss.getSubPrimeFieldOrder();
		CommitmentScheme commitmentScheme = vss.getCommitmentScheme();
		for (int faultyC = minFaultyC; faultyC <= maxFaultyC; faultyC++) {
			if (faultyC > 0)
				System.out.println();
			System.out.println("Faulty server(s): " + faultyC);
			BigInteger secret = new BigInteger(field.bitLength() - 1, rndGenerator);
			Polynomial secretPolynomial = new Polynomial(field, threshold, secret, rndGenerator);
			BigInteger recoveryShareholder = shareholders[0];
			System.out.println("Recovering shareholder: " + recoveryShareholder);
			Commitment commitment = commitmentScheme.generateCommitments(secretPolynomial);
			Map<BigInteger, Commitment> commitments = new HashMap<>(n);

			for (int i = 0; i < n; i++) {
				BigInteger shareholder = shareholders[i];
				if (shareholder.equals(recoveryShareholder))
					continue;
				commitments.put(shareholder,
						commitmentScheme.extractCommitment(shareholder,
								commitment));
			}

			//corrupting witnesses
			Set<BigInteger> corruptedShareholders = new HashSet<>(faultyC);
			BigInteger donorShareholder;
			Iterator<BigInteger> it = commitments.keySet().iterator();
			do {
				donorShareholder = it.next();
			} while (donorShareholder.equals(recoveryShareholder));
			Commitment donorShareCommitment = commitments.get(donorShareholder);
			int alreadyCorrupted = 0;
			while (it.hasNext() && alreadyCorrupted < faultyC) {
				BigInteger corruptedShareholder = it.next();
				if (corruptedShareholder.equals(recoveryShareholder)) {
					continue;
				}
				Commitment corruptedCommitment = corruptCommitment(donorShareCommitment);
				commitments.put(corruptedShareholder, corruptedCommitment);
				corruptedShareholders.add(corruptedShareholder);
				alreadyCorrupted++;
				System.out.println("Corrupted commitment of shareholder " + corruptedShareholder);
			}

			Commitment recoveredCommitment = null;
			try {
				recoveredCommitment = commitmentScheme.recoverCommitment(recoveryShareholder,
						commitments);
			} catch (SecretSharingException e) {
				System.out.println("Found faulty commitments");
				Map<BigInteger, Commitment> validCommitments = new HashMap<>(threshold + 1);
				for (Map.Entry<BigInteger, Commitment> entry : commitments.entrySet()) {
					if (corruptedShareholders.contains(entry.getKey()))
						continue;
					validCommitments.put(entry.getKey(), entry.getValue());
					if (validCommitments.size() == threshold + 1)
						break;
				}

				try {
					recoveredCommitment =
							commitmentScheme.recoverCommitment(recoveryShareholder, validCommitments);
				} catch (SecretSharingException ex) {
					System.err.println("This should not happen");
					System.exit(-1);
				}
			}

			if (!recoveredCommitment.equals(commitmentScheme.extractCommitment(recoveryShareholder, commitment)))
				throw new IllegalStateException("Commitments are different");

		}
	}

	private static Commitment corruptCommitment(Commitment donorShareCommitment) {
		if (donorShareCommitment instanceof LinearCommitments) {
			LinearCommitments linearCommitment = (LinearCommitments) donorShareCommitment;
			BigInteger[] commitments = linearCommitment.getCommitments();
			BigInteger[] copyCommitments = Arrays.copyOf(commitments, commitments.length);
			copyCommitments[0] = copyCommitments[1];
			return new LinearCommitments(copyCommitments);
		} else if (donorShareCommitment instanceof ECLinearCommitment) {
			ECLinearCommitment ecLinearCommitment = (ECLinearCommitment) donorShareCommitment;
			ECPoint[] commitments = ecLinearCommitment.getCommitments();
			ECPoint[] copyCommitments = Arrays.copyOf(commitments, commitments.length);
			copyCommitments[0] = copyCommitments[1];
			return new ECLinearCommitment(copyCommitments, copyCommitments[0].getCurve());
		} else if (donorShareCommitment instanceof RawLinearCommitment) {
			RawLinearCommitment rawLinearCommitment = (RawLinearCommitment) donorShareCommitment;
			byte[][] commitments = rawLinearCommitment.getCommitments();
			byte[][] copyCommitments = Arrays.copyOf(commitments, commitments.length);
			copyCommitments[0] = copyCommitments[1];
			return new RawLinearCommitment(copyCommitments);
		} else if (donorShareCommitment instanceof ShareKZGCommitment) {
			return donorShareCommitment;
		} else {
			throw new IllegalArgumentException("Unknown commitment type");
		}
	}
}
