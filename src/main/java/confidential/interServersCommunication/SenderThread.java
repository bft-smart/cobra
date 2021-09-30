package confidential.interServersCommunication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.LinkedBlockingQueue;

/**
 * Copy of bftsmart.communication.server.ServerConnection.SenderThread.java
 */
public class SenderThread extends Thread {
    private final Logger logger = LoggerFactory.getLogger("communication");
    private final int remoteId;
    private final LinkedBlockingQueue<byte[]> outQueue;
    private final Connection connection;

    public SenderThread(int remoteId, LinkedBlockingQueue<byte[]> outQueue, Connection connection) {
        super("Sender Thread for " + remoteId);
        this.remoteId = remoteId;
        this.outQueue = outQueue;
        this.connection = connection;
    }

    @Override
    public void run() {
        byte[] data;
        while (connection.isDoingWork()) {
            try {
                data = outQueue.take();
                connection.sendBytes(data);
            } catch (InterruptedException ignored) {
                break;
            }
        }

        logger.debug("Exiting sender thread for {}", remoteId);
    }
}
