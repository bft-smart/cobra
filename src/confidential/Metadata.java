package confidential;

/**
 * @author Robin
 */
public enum Metadata {
    POLYNOMIAL_PROPOSAL_SET;

    public static Metadata[] values = values();

    public static Metadata getMessageType(int ordinal) {
        return values[ordinal];
    }
}
