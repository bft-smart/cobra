package confidential.server;

import bftsmart.communication.ServerCommunicationSystem;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.core.messages.ForwardedMessage;
import bftsmart.tom.core.messages.TOMMessage;
import confidential.MessageType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;

public class InterServersCommunication {
    private final TOMMessageGenerator tomMessageGenerator;
    private final ServerCommunicationSystem communicationSystem;

    public InterServersCommunication(ServerCommunicationSystem communicationSystem, ServerViewController viewController) {
        this.tomMessageGenerator = new TOMMessageGenerator(viewController);
        this.communicationSystem = communicationSystem;
    }

    public void sendOrdered(byte[] request, int... targets) {
        TOMMessage msg = tomMessageGenerator.getNextOrdered(serializeRequest(request));
        communicationSystem.send(targets, new ForwardedMessage(msg.getSender(), msg));
    }

    public void sendUnordered(byte[] request, int... targets) {
        TOMMessage msg = tomMessageGenerator.getNextUnordered(serializeRequest(request));
        communicationSystem.send(targets, new ForwardedMessage(msg.getSender(), msg));
    }

    private byte[] serializeRequest(byte[] request) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte) MessageType.APPLICATION.ordinal());
            out.writeInt(request == null ? -1 : request.length);
            if (request != null)
                out.write(request);
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
