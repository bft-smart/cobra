package confidential.interServersCommunication;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.LinkedBlockingQueue;

public abstract class MessageListener extends Thread {
    private final Logger logger = LoggerFactory.getLogger("communication");
    private final LinkedBlockingQueue<InternalMessage> messages;
    private final byte communicationTag;

    public MessageListener(byte communicationTag) {
        super("Exiting Message Listener Thread for " + communicationTag);
        this.communicationTag = communicationTag;
        this.messages = new LinkedBlockingQueue<>();
    }

    public byte getCommunicationTag() {
        return communicationTag;
    }

    public void messageReceived(InternalMessage message) {
        messages.offer(message);
    }

    public abstract void deliverMessage(InternalMessage message);

    @Override
    public void run() {
        while (true) {
            try {
                InternalMessage m = messages.take();
                logger.debug("I have message with tag {} to deliver", communicationTag);
                try {
                    deliverMessage(m);
                } catch (Exception e) {
                    logger.warn("Failed to deliver a message with tag {}", communicationTag);
                }
            } catch (InterruptedException e) {
                logger.error("Failed to take message from queue", e);
                break;
            }
        }
        logger.debug("Exiting message listener thread for {}", communicationTag);
    }
}
