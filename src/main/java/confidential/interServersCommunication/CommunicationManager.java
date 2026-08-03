package confidential.interServersCommunication;

import bftsmart.reconfiguration.ServerViewController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.concurrent.LinkedBlockingQueue;

public class CommunicationManager extends Thread {
    private final Logger logger = LoggerFactory.getLogger("communication");
    private boolean doWork;
    private final LinkedBlockingQueue<InternalMessage> inQueue;
    private final HashMap<Byte, MessageListener> messageListeners;
    private final ConnectionManager connectionManager;

    public CommunicationManager(ServerViewController svController) {
        super("Communication Manager Thread");
        this.doWork = true;
        this.inQueue = new LinkedBlockingQueue<>(svController.getStaticConf().getInQueueSize());
        this.messageListeners = new HashMap<>();
        try {
            this.connectionManager = new ConnectionManager(svController, inQueue);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize connection manager", e);
        }
        this.connectionManager.start();
    }

    public boolean registerMessageListener(MessageListener listener) {
        byte tag = listener.getCommunicationTag();
        if (messageListeners.containsKey(tag))
            return false;
        messageListeners.put(tag, listener);
        return true;
    }

    @Override
    public void run() {
        while (doWork) {
            try {
                InternalMessage message = inQueue.take();

                logger.debug("Received a message with tag {}", message.getCommunicationTag());
                MessageListener listener = messageListeners.get(message.getCommunicationTag());
                if (listener == null) {
                    logger.warn("There is no listener for tag {}", message.getCommunicationTag());
                    continue;
                }
                listener.messageReceived(message);
            } catch (InterruptedException e) {
                logger.error("Failed to take internal message from inQueue", e);
                break;
            }
        }

        logger.debug("Exiting communication manager thread");
    }

    public void send(byte communicationTag, InternalMessage message, int... targets) {
        connectionManager.send(communicationTag, message, targets);
    }

    public void shutdown() {
        logger.info("Shutting down communication manager");
        doWork = false;
        connectionManager.shutdown();
    }
}
