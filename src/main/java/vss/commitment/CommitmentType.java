package vss.commitment;

/**
 * @author Robin
 */
public enum CommitmentType {
    LINEAR, //contains a vector of commitments
    CONSTANT, //contains a commitment and all the witnesses
    SHARE_COMMITMENT, //contains only a commitment and a witness
    ELLIPTIC_CURVE; //contains a vector of commitments based on elliptic curve

    private static final CommitmentType[] types = values();

    public static CommitmentType getType(int ordinal) {
        return types[ordinal];
    }
}
