package confidential;

/**
 * @author Robin
 */
public enum Metadata {
    VERIFY,
    DOES_NOT_VERIFY,
    POLYNOMIAL_PROPOSAL_SET;

    public static Metadata[] values = values();

    public static Metadata getMessageType(int ordinal) {
        return values[ordinal];
    }
}
