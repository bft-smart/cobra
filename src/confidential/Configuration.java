package confidential;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;

public final class Configuration {
	private static String configurationFilePath =
			"config" + File.separator + "cobra.config";
	private long renewalPeriod;
	private boolean renewalActive;
	private String vssScheme;
	private String primeField;
	private String subPrimeField;
	private String generator;
	private String dataEncryptionAlgorithm = "AES";
	private String shareEncryptionAlgorithm = "AES";
	private int recoveryPort;
	private boolean useTLSEncryption;
	private int shareProcessingThreads;
	private boolean verifyClientRequests;
	private final BigInteger[] vandermondeMatrixInitializationValues;

	private static Configuration INSTANT;
	private boolean sendAllSharesTogether;

	public static void setConfigurationFilePath(String configurationFilePath) {
		Configuration.configurationFilePath = configurationFilePath;
	}

	public static Configuration getInstance() {
		if (INSTANT == null) {
			try {
				INSTANT = new Configuration(configurationFilePath);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return INSTANT;
	}

	private Configuration(String configurationFilePath) throws IOException {
		vandermondeMatrixInitializationValues = new BigInteger[] {
				new BigInteger("751789666dcf511e320c131e65fe5760320ddf491855afbe9dbb6704af354274", 16),
				new BigInteger("15a86bc7717d4d12b01783f4a5a127f28b8bf2d2ecc40f8a95ac27b1b14fdd0", 16),
				new BigInteger("61ba52f6aa9bd8f8a2dc42fde82f560cff927cad086b28e9c11bd1070f510a4c", 16),
				new BigInteger("2ea8e3491df98884b1d071e62266cf8efc32379b40078365329ffe3d4979e3d4", 16),
				new BigInteger("1b5383488a085f20ccb85f86dd9de76602b5802276644f3336e57f2f2cb0d1f0", 16),
				new BigInteger("54f050ff3b4bf3115ba98693c0c7d05245b9b635549b8a7e50292e493862ced8", 16),
				new BigInteger("3a2d7b33f1d6bcfb99faa864b382505d7e1e3ba3a0c48456f704dd4458cd846e", 16),
				new BigInteger("5839071d3045a49a93138199d307722d5c44bdb54893f4ab747af4892eb42c48", 16),
				new BigInteger("406821cdfd57086eb6b483e4d87abd060c503d07394b1ef590a49dc322a4cc89", 16),
				new BigInteger("1b45866f373f4e268835fccb174ad6add3212dc3f1920f21b16ae920d5e2bddd", 16)
		};

		try (BufferedReader in = new BufferedReader(new FileReader(configurationFilePath))) {
			String line;
			while ((line = in.readLine()) != null) {
				if (line.startsWith("#")) {
					continue;
				}
				String[] tokens = line.split("=");
				if (tokens.length != 2)
					continue;
				String propertyName = tokens[0].trim();
				String value = tokens[1].trim();
				switch (propertyName) {
					case "cobra.vss.scheme":
						if (value.equals("linear"))
							vssScheme = "1";
						else if (value.equals("constant"))
							vssScheme = "2";
						else
							throw new IllegalArgumentException("Property cobra.vss.scheme " +
									"has invalid value");
						break;
					case "cobra.vss.prime_field":
						primeField = value;
						break;
					case "cobra.vss.sub_field":
						subPrimeField = value;
						break;
					case "cobra.vss.generator":
						generator = value;
						break;
					case "cobra.vss.data_encryption_algorithm":
						dataEncryptionAlgorithm = value;
						break;
					case "cobra.vss.share_encryption_algorithm":
						shareEncryptionAlgorithm = value;
						break;
					case "cobra.recovery.port":
						recoveryPort = Integer.parseInt(value);
						break;
					case "cobra.renewal.active":
						renewalActive = Boolean.parseBoolean(value);
						break;
					case "cobra.renewal.period":
						renewalPeriod = Long.parseLong(value);
						break;
					case "cobra.communication.use_tls_encryption":
						useTLSEncryption = Boolean.parseBoolean(value);
						break;
					case "cobra.share_processing_threads":
						shareProcessingThreads = Integer.parseInt(value);
						break;
					case "cobra.verify.requests":
						verifyClientRequests = Boolean.parseBoolean(value);
						break;
					case "cobra.send_all_shares_together":
						sendAllSharesTogether = Boolean.parseBoolean(value);
						break;
					default:
						throw new IllegalArgumentException("Unknown property name");
				}
			}
		}
	}

	public BigInteger[] getVandermondeMatrixInitializationValues() {
		return vandermondeMatrixInitializationValues;
	}

	public int getShareProcessingThreads() {
		return shareProcessingThreads;
	}

	public boolean isVerifyClientRequests() {
		return verifyClientRequests;
	}

	public long getRenewalPeriod() {
		return renewalPeriod;
	}

	public boolean isRenewalActive() {
		return renewalActive;
	}

	public String getVssScheme() {
		return vssScheme;
	}

	public String getPrimeField() {
		return primeField;
	}

	public String getSubPrimeField() {
		return subPrimeField;
	}

	public String getGenerator() {
		return generator;
	}

	public String getDataEncryptionAlgorithm() {
		return dataEncryptionAlgorithm;
	}

	public String getShareEncryptionAlgorithm() {
		return shareEncryptionAlgorithm;
	}

	public int getRecoveryPort() {
		return recoveryPort;
	}

	public boolean useTLSEncryption() {
		return useTLSEncryption;
	}

	public boolean isSendAllSharesTogether() {
		return sendAllSharesTogether;
	}
}
