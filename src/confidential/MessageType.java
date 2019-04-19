package confidential;

public enum  MessageType {
    EMPTY, //message without plain data or secret data
    PLAIN, //message with only plain data
    SINGLE, //message with only one secret
    MULTIPLE, //message with multiple secrets
    PLAIN_SINGLE, //message with plain data and one secret
    PLAIN_MULTIPLE; //message with plain data and multiple secrets

    public static MessageType[] values = values();

    public static MessageType getOperation(int ordinal) {
        return values[ordinal];
    }
}
