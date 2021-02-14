package confidential.interServersCommunication;

import bftsmart.communication.ServerCommunicationSystem;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.core.messages.ForwardedMessage;
import bftsmart.tom.core.messages.TOMMessage;
import confidential.MessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class InterServersCommunication {
    private final Logger logger = LoggerFactory.getLogger("communication");
    private final TOMMessageGenerator tomMessageGenerator;
    private final ServerCommunicationSystem communicationSystem;
    private final Map<InterServersMessageType, InterServerMessageListener> listeners;
    private final CommunicationManager communicationManager;
    private final int pid;

    public InterServersCommunication(ServerCommunicationSystem communicationSystem, ServerViewController viewController) {
        this.tomMessageGenerator = new TOMMessageGenerator(viewController);
        this.communicationSystem = communicationSystem;
        this.listeners = new HashMap<>();
        this.communicationManager = new CommunicationManager(viewController);
        this.communicationManager.start();
        this.pid = viewController.getStaticConf().getProcessId();
    }

    public synchronized void sendOrdered(InterServersMessageType type, byte[] metadata, byte[] request,
                            int... targets) {
        TOMMessage msg = tomMessageGenerator.getNextOrdered(metadata,
                serializeRequest(type, request));
        communicationSystem.send(targets, new ForwardedMessage(msg.getSender(), msg));
    }

    public boolean registerListener(MessageListener listener) {
        return communicationManager.registerMessageListener(listener);
    }

    public synchronized void sendUnordered(CommunicationTag tag, InterServersMessageType type,
                                           byte[] request, int... targets) {
        byte[] message = serializeInternalRequest(type, request);
        communicationManager.send(tag, new InternalMessage(pid, tag, message), targets);
    }

    public void registerListener(InterServerMessageListener listener, InterServersMessageType messageType,
                                 InterServersMessageType... moreMessageTypes) {
        listeners.put(messageType, listener);
        for (InterServersMessageType type : moreMessageTypes)
            listeners.put(type, listener);
    }

    public void messageReceived(byte[] message, MessageContext msgCtx) {
        InterServersMessageType type = InterServersMessageType.getType(message[0]);
        byte[] m = Arrays.copyOfRange(message, 1, message.length);
        InterServerMessageListener listener = listeners.get(type);
        if (listener == null)
            logger.warn("Listener for message type {} not found", type);
        else {
            InterServerMessageHolder holder = new InterServerMessageHolder(type, m, msgCtx);
            listener.messageReceived(holder);
        }
    }

    private byte[] serializeInternalRequest(InterServersMessageType type, byte[] request) {
        byte[] result = new byte[request.length + 1];
        result[0] = (byte) type.ordinal();
        System.arraycopy(request, 0, result, 1, request.length);
        return result;
    }

    private byte[] serializeRequest(InterServersMessageType type, byte[] request) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte) MessageType.APPLICATION.ordinal());
            out.writeInt(1 + request.length);
            out.write((byte)type.ordinal());
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
