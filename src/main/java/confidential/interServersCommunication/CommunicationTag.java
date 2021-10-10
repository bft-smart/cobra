package confidential.interServersCommunication;

public enum CommunicationTag {
    POLYNOMIAL;

    private static final CommunicationTag[] values = CommunicationTag.values();

    public static CommunicationTag getTag(int ordinal) {
        return values[ordinal];
    }
}
