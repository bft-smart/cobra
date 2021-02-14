package confidential.interServersCommunication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Copy of bftsmart.communication.server.ServerConnection.ReceiverThread.java
 */
public class ReceiverThread extends Thread {
    private final Logger logger = LoggerFactory.getLogger("communication");
    private final int remoteId;
    private final LinkedBlockingQueue<InternalMessage> inQueue;
    private SSLSocket socket;
    private DataInputStream socketInStream;
    private final Connection connection;

    public ReceiverThread(int remoteId, LinkedBlockingQueue<InternalMessage> inQueue, SSLSocket socket,
                          DataInputStream socketInStream, Connection connection) {
        super("Receiver Thread for " + remoteId);
        this.remoteId = remoteId;
        this.inQueue = inQueue;
        this.socket = socket;
        this.socketInStream = socketInStream;
        this.connection = connection;
    }

    @Override
    public void run() {
        while (connection.isDoingWork()) {
            if (socket != null && socketInStream != null) {
                try {
                    int dataLength = socketInStream.readInt();
                    byte[] data = new byte[dataLength];
                    int read = 0;
                    do {
                        read += socketInStream.read(data, read, dataLength - read);
                    } while (read < dataLength);

                    byte hasMAC = socketInStream.readByte();
                    logger.debug("Read: {}, HashMAC: {}", read, hasMAC);

                    try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
                         ObjectInput in = new ObjectInputStream(bis)) {
                        InternalMessage message = new InternalMessage();
                        message.readExternal(in);

                        if (message.getSender() == remoteId) {
                            if (!inQueue.offer(message)) {
                                logger.warn("InQueue full (message from {} discarded)", remoteId);
                            }
                        }
                    } catch (ClassNotFoundException e) {
                        logger.warn("Invalid message received. Ignoring!");
                    }

                } catch (IOException e) {
                    if (connection.isDoingWork()) {
                        logger.debug("Closing socket and reconnecting");
                        connection.closeSocket();
                        connection.waitAndConnect();
                    }
                }
            } else {
                connection.waitAndConnect();
            }
        }

        logger.debug("Exiting sender thread for {}", remoteId);
    }

    public void updateConnection(SSLSocket socket, DataInputStream socketInStream) {
        this.socket = socket;
        this.socketInStream = socketInStream;
    }
}
