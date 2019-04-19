package confidential.client;

public class Response {
    private final byte[] painData;
    private final byte[][] confidentialData;

    public Response(byte[] painData, byte[][] confidentialData) {
        this.painData = painData;
        this.confidentialData = confidentialData;
    }

    public byte[] getPainData() {
        return painData;
    }

    public byte[][] getConfidentialData() {
        return confidentialData;
    }
}
