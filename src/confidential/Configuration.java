package confidential;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

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

	public static final BigInteger[] defaultKeys = {
			new BigInteger("937810634060551071826485204471949219646466658841719067506"),
			new BigInteger("2070500848756246996383345868621307412466502332353200391602"),
			new BigInteger("225622465560524539505877757960043111882233204074971325789"),
			new BigInteger("1251496368993253749696877697566511976712060271562136483661"),
			new BigInteger("1251496368993253749696877697566511976712060271562136483661"),
			new BigInteger("1251496368993253749696877697566511976712060271562136483661"),
			new BigInteger("1251496368993253749696877697566511976712060271562136483661"),
			new BigInteger("1251496368993253749696877697566511976712060271562136483661"),
			new BigInteger("1251496368993253749696877697566511976712060271562136483661"),
			new BigInteger("1251496368993253749696877697566511976712060271562136483661")
	};

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
				String propertyName = tokens[0];
				String value = tokens[1];
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
					default:
						throw new IllegalArgumentException("Unknown property name");
				}
			}
		}
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
}
