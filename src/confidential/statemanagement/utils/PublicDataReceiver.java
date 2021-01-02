package confidential.statemanagement.utils;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.reconfiguration.views.View;
import confidential.Configuration;
import confidential.Utils;
import confidential.statemanagement.resharing.BlindedStateHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

public class PublicDataReceiver extends Thread {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final BlindedStateHandler blindedStateHandler;
    private final ServerViewController svController;
    private final int serverPort;
    private final int stateSender;
    private final Set<String> knownServersIp;
    private final boolean isLinearCommitmentScheme;

    public PublicDataReceiver(BlindedStateHandler blindedStateHandler,
                              ServerViewController svController,
                              int serverPort,
                              int stateSender, int[] receiversId) throws IOException {
        super("Public Data Receiver Thread");
        this.blindedStateHandler = blindedStateHandler;
        this.svController = svController;
        this.serverPort = serverPort;
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
        try (ServerSocket serverSocket = new ServerSocket()) {
            String myIp = svController.getStaticConf()
                    .getLocalAddress(svController.getStaticConf().getProcessId())
                    .getAddress().getHostAddress();
            serverSocket.bind(new InetSocketAddress(myIp, serverPort));
            logger.debug("Listening for public data on {}:{}",
                    serverSocket.getInetAddress().getHostAddress(), serverSocket.getLocalPort());
            while (true) {
                try (Socket client = serverSocket.accept()) {
                    client.setKeepAlive(true);
                    client.setTcpNoDelay(true);

                    String clientIp = client.getInetAddress().getHostAddress();
                    if (!knownServersIp.contains(clientIp)) {
                        logger.warn("Received connection from unknown server with ip {}. Ignoring", clientIp);
                        continue;
                    }
                    logger.debug("Received unencrypted connection from {}", clientIp);

                    BufferedInputStream in = new BufferedInputStream(client.getInputStream());
                    long start, end;
                    start = System.nanoTime();
                    int pid = Utils.toNumber(Utils.readNBytes(4, in));

                    int len = Utils.toNumber(Utils.readNBytes(4, in));
                    logger.info("Going to receive {} bytes of blinded shares from {}", len, pid);
                    byte[] serializedBlindedShares = Utils.readNBytes(len, in);

                    len = Utils.toNumber(Utils.readNBytes(4, in));
                    logger.info("Going to receive {} bytes of commitments from {}", len, pid);
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
                    logger.info("Going to receive {} bytes of common state from {}", len, pid);
                    if (pid != stateSender) {
                        commonStateHash = Utils.readNBytes(len, in);
                    } else {
                        commonState = new byte[len];
                        commonStateHash = readAndComputeHash(in, len, commonState);
                    }
                    end = System.nanoTime();
                    double duration = (end - start) / 1_000_000.0;
                    logger.info("Took {} ms to receive data from {}", duration, pid);
                    blindedStateHandler.deliverPublicState(pid, serializedBlindedShares,
                            commitments, commitmentHash, commonState, commonStateHash);

                } catch (IOException e) {
                    break;
                } catch (NoSuchAlgorithmException e) {
                    logger.error("Failed to initialize Hash Thread", e);
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
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
        int offset = 0;
        int n = len;
        while (n > 0) {
            int received = in.read(dataHolder, offset, n);
            hashThread.update(offset, received);
            offset += received;
            n -= received;
        }
        hashThread.update(-1, -1);
        return hashThread.getHash();
    }
}
