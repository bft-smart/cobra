package confidential.server;

import confidential.MessageType;
import vss.secretsharing.VerifiableShare;

public final class ClientMessage extends Message {
    private byte[] plainData;
    private VerifiableShare[] shares;

    public ClientMessage(MessageType messageType, byte[] plainData, VerifiableShare... shares) {
        super(messageType);
        this.plainData = plainData;
        this.shares = shares;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public VerifiableShare[] getShares() {
        return shares;
    }
}
