package confidential.server;

import bftsmart.communication.ServerCommunicationSystem;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.core.messages.ForwardedMessage;
import bftsmart.tom.core.messages.TOMMessage;

public class InterServersCommunication {
    private final TOMMessageGenerator tomMessageGenerator;
    private final ServerCommunicationSystem communicationSystem;

    public InterServersCommunication(ServerCommunicationSystem communicationSystem, ServerViewController viewController) {
        this.tomMessageGenerator = new TOMMessageGenerator(viewController);
        this.communicationSystem = communicationSystem;
    }

    public void sendOrdered(byte[] request, int... targets) {
        TOMMessage msg = tomMessageGenerator.getNextOrdered(request);
        communicationSystem.send(targets, new ForwardedMessage(msg.getSender(), msg));
    }

    public void sendUnordered(byte[] request, int... targets) {
        TOMMessage msg = tomMessageGenerator.getNextUnordered(request);
        communicationSystem.send(targets, new ForwardedMessage(msg.getSender(), msg));
    }
}
