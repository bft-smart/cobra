package vss.commitment;

public enum CommitmentSchemeType {
	FELDMAN_SCHEME,
	EC_FELDMAN_SCHEME,
	C_EC_FELDMAN_SCHEME,
	DL_KZG_SCHEME,
	PED_KZG_SCHEME;

	public static CommitmentSchemeType getType(String designation) {
		switch (designation) {
			case "linear":
				return CommitmentSchemeType.FELDMAN_SCHEME;
			case "ec_linear":
				return CommitmentSchemeType.EC_FELDMAN_SCHEME;
			case "c_ec_linear":
				return CommitmentSchemeType.C_EC_FELDMAN_SCHEME;
			case "dl_kzg":
				return CommitmentSchemeType.DL_KZG_SCHEME;
			case "ped_kzg":
				return CommitmentSchemeType.PED_KZG_SCHEME;
			default:
				throw new IllegalArgumentException("Unknown commitment scheme designation: " + designation);
		}
	}
}
