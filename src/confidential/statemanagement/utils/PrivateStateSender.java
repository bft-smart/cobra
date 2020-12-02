package confidential.statemanagement.utils;

import confidential.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedOutputStream;
import java.io.IOException;

public class PrivateStateSender extends Thread {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final String receiverServerIp;
    private final int receiverServerPort;
    private final byte[] state;
    private final int processId;
    private final SSLSocketFactory socketFactory;

    public PrivateStateSender(String receiverServerIp, int receiverServerPort, byte[] state, int processId, SSLSocketFactory socketFactory) {
        super("Common State Sender Thread");
        this.receiverServerIp = receiverServerIp;
        this.receiverServerPort = receiverServerPort;
        this.state = state;
        this.processId = processId;
        this.socketFactory = socketFactory;
    }

    @Override
    public void run() {
        logger.debug("Connecting securely to {}:{}", receiverServerIp, receiverServerPort);
        try (SSLSocket connection = (SSLSocket) socketFactory.createSocket(receiverServerIp, receiverServerPort);
             BufferedOutputStream out = new BufferedOutputStream(connection.getOutputStream())) {
            long t1, t2;
            logger.info("Private state has {} bytes", state.length);
            t1 = System.nanoTime();
            out.write(Utils.toBytes(processId));
            out.write(Utils.toBytes(state.length));
            out.write(state);
            out.flush();
            t2 = System.nanoTime();
            logger.info("Took {} ms to send private state", (t2 - t1) / 1_000_000.0);
        } catch (IOException e) {
            logger.error("Failed to send public state to {}:{}.", receiverServerIp, receiverServerPort);
        }
    }
}
