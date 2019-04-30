package confidential.server;

import confidential.MessageType;

public final class ServerMessage extends Message {

    public ServerMessage(MessageType messageType) {
        super(messageType);
    }
}
