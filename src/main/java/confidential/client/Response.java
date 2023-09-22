package confidential.client;

public class Response {
    private final byte[] plainData;
    private final byte[][] confidentialData;

    public Response(byte[] plainData, byte[][] confidentialData) {
        this.plainData = plainData;
        this.confidentialData = confidentialData;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public byte[][] getConfidentialData() {
        return confidentialData;
    }
}
