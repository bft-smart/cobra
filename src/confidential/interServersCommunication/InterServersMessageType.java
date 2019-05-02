package confidential.interServersCommunication;

public enum InterServersMessageType {
    NEW_POLYNOMIAL,
    POLYNOMIAL_PROPOSAL, POLYNOMIAL_PROPOSAL_SET, POLYNOMIAL_VOTE, POLYNOMIAL_MISSING_PROPOSALS, POLYNOMIAL_PROCESSED_VOTES;

    private static InterServersMessageType[] values = InterServersMessageType.values();

    public static InterServersMessageType getType(int ordinal) {
        return values[ordinal];
    }
}
