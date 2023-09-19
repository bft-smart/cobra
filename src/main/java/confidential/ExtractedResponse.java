package confidential;

import bftsmart.tom.util.ServiceResponse;
import vss.facade.SecretSharingException;

import java.io.*;

public class ExtractedResponse extends ServiceResponse {
    private final byte[][] confidentialData;
    private final SecretSharingException throwable;

    public ExtractedResponse(byte[] plainData, byte[][] confidentialData, SecretSharingException throwable) {
		super(plainData);
        this.confidentialData = confidentialData;
        this.throwable = throwable;
    }

    public ExtractedResponse(byte[] plainData, byte[][] confidentialData) {
        super(plainData);
        this.confidentialData = confidentialData;
        this.throwable = null;
    }

    public SecretSharingException getThrowable() {
        return throwable;
    }

    public byte[][] getConfidentialData() {
        return confidentialData;
    }
}
