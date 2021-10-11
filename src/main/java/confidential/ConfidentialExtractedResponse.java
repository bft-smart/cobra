package confidential;

import bftsmart.tom.util.ExtractedResponse;
import vss.facade.SecretSharingException;

public class ConfidentialExtractedResponse extends ExtractedResponse {
    private final byte[][] confidentialData;
    private final SecretSharingException throwable;

    public ConfidentialExtractedResponse(int viewID, byte[] plainData) {
        super(viewID, plainData);
        confidentialData = null;
        throwable = null;
    }

    public ConfidentialExtractedResponse(int viewID, byte[] plainData, byte[][] confidentialData, SecretSharingException throwable) {
        super(viewID, plainData);
        this.confidentialData = confidentialData;
        this.throwable = throwable;
    }

    public ConfidentialExtractedResponse(int viewID, byte[] plainData, byte[][] confidentialData) {
        super(viewID, plainData);
        this.confidentialData = confidentialData;
        this.throwable = null;
    }

    public SecretSharingException getThrowable() {
        return throwable;
    }

    public byte[] getPlainData() {
        return getContent();
    }

    public byte[][] getConfidentialData() {
        return confidentialData;
    }
}