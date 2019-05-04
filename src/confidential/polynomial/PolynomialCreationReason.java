package confidential.polynomial;

public enum PolynomialCreationReason {
    RECOVERY,
    RESHARING;

    private static PolynomialCreationReason[] values = values();

    public static PolynomialCreationReason getReason(int ordinal) {
        return values[ordinal];
    }
}
