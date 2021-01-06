package confidential;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

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

	private static Configuration INSTANT;

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
					default:
						throw new IllegalArgumentException("Unknown property name");
				}
			}
		}
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
}
