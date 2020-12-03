package confidential.statemanagement.utils;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.reconfiguration.views.View;
import confidential.Configuration;
import confidential.Utils;
import confidential.statemanagement.resharing.BlindedStateHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

public class PublicDataReceiver extends Thread {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final BlindedStateHandler blindedStateHandler;
    private final int stateSender;
    private final Set<String> knownServersIp;
    private final ServerSocket serverSocket;
    private final boolean isLinearCommitmentScheme;

    public PublicDataReceiver(BlindedStateHandler blindedStateHandler,
                              ServerViewController svController,
                              int serverPort,
                              int stateSender, int[] receiversId) throws IOException {
        super("Public Data Receiver Thread");
        this.blindedStateHandler = blindedStateHandler;
        this.serverSocket = ServerSocketFactory.getDefault().createServerSocket(serverPort);
        this.stateSender = stateSender;
        this.knownServersIp = new HashSet<>(receiversId.length);
        View cv = svController.getCurrentView();
        for (int id : receiversId) {
            knownServersIp.add(cv.getAddress(id).getAddress().getHostAddress());
        }
        this.isLinearCommitmentScheme = Configuration.getInstance().getVssScheme().equals("1");
    }

    @Override
    public void run() {
        logger.debug("Listening for public data on {}:{}", serverSocket.getInetAddress().getHostName(), serverSocket.getLocalPort());
        while (true) {
            try (Socket client = serverSocket.accept()) {
                client.setKeepAlive(true);
                client.setTcpNoDelay(true);

                String clientIp = client.getInetAddress().getHostAddress();

                if (!knownServersIp.contains(clientIp)) {
                    logger.info("Received connection from unknown server with ip {}. Ignoring", clientIp);
                    continue;
                }

                BufferedInputStream in = new BufferedInputStream(client.getInputStream());
                int pid = Utils.toNumber(Utils.readNBytes(4, in));
                logger.debug("Received unencrypted connection from {}", pid);

                int len = Utils.toNumber(Utils.readNBytes(4, in));
                logger.debug("Going to receive {} bytes fo blinded shares from {}", len, pid);
                byte[] serializedBlindedShares = Utils.readNBytes(len, in);

                len = Utils.toNumber(Utils.readNBytes(4, in));
                logger.debug("Going to receive {} bytes of commitments from {}", len, pid);
                byte[] commitments = null;
                byte[] commitmentHash = null;
                if (!isLinearCommitmentScheme) {
                    commitments = Utils.readNBytes(len, in);//constant commitments
                } else if (pid != stateSender) {
                    commitmentHash = Utils.readNBytes(len, in);//this is only hash
                } else {
                    commitments = new byte[len];
                    commitmentHash = readAndComputeHash(in, len, commitments);
                }

                byte[] commonState = null;
                byte[] commonStateHash;

                len = Utils.toNumber(Utils.readNBytes(4, in));
                logger.debug("Going to receive {} bytes of common state from {}", len, pid);
                if (pid != stateSender) {
                    commonStateHash = Utils.readNBytes(len, in);
                } else {
                    commonState = new byte[len];
                    commonStateHash = readAndComputeHash(in, len, commonState);
                }

                blindedStateHandler.deliverPublicState(pid, serializedBlindedShares,
                        commitments, commitmentHash, commonState, commonStateHash);

            } catch (IOException e) {
                break;
            } catch (NoSuchAlgorithmException e) {
                logger.error("Failed to initialize Hash Thread", e);
            }
        }

        logger.debug("Exiting public data receiver thread");
    }

    /**
     * dataHolder will have received data and method will return hash of dataHolder
     * @param in Input Stream
     * @param len Number of bytes to read
     * @param dataHolder Holder for received data
     * @return Hash of dataHolder
     * @throws NoSuchAlgorithmException Fails to initialize hash thread
     * @throws IOException Fails to read data
     */
    private byte[] readAndComputeHash(BufferedInputStream in, int len, byte[] dataHolder) throws NoSuchAlgorithmException, IOException {
        HashThread hashThread = new HashThread();
        hashThread.setData(dataHolder);
        hashThread.start();
        int j = 0;
        while (j < len) {
            int received = in.read(dataHolder, j, len);
            hashThread.update(j, received);
            j += received;
        }
        hashThread.update(-1, -1);
        return hashThread.getHash();
    }

    @Override
    public void interrupt() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            logger.error("Failed to close server socket", e);
        }
        super.interrupt();
    }
}
