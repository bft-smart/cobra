package confidential.interServersCommunication;

public enum InterServersMessageType {
    NEW_POLYNOMIAL,
    POLYNOMIAL_PROPOSAL,
    POLYNOMIAL_PROPOSAL_SET,
    POLYNOMIAL_VOTE,
    POLYNOMIAL_REQUEST_MISSING_PROPOSALS,
    POLYNOMIAL_PROCESSED_VOTES,
    POLYNOMIAL_MISSING_PROPOSALS;

    private static InterServersMessageType[] values = InterServersMessageType.values();

    public static InterServersMessageType getType(int ordinal) {
        return values[ordinal];
    }
}
