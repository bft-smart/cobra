package confidential.statemanagement.privatestate.receiver;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.reconfiguration.views.View;
import confidential.Configuration;
import confidential.statemanagement.utils.HashThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.Utils;
import vss.commitment.Commitment;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

public class BlindedDataReceiver extends Thread {
    private final Logger logger = LoggerFactory.getLogger("state_transfer");
    private final BlindedStateHandler blindedStateHandler;
    private final Set<String> knownServerIps;
    private final ServerViewController svController;
    private final int serverPort;
    private final int quorum;
    private final int stateSenderReplica;

    public BlindedDataReceiver(BlindedStateHandler blindedStateHandler, ServerViewController svController,
                               int serverPort, int quorum, int stateSenderReplica) throws IOException {
        super("Blinded Data Receiver Thread");
        this.blindedStateHandler = blindedStateHandler;
        this.svController = svController;
        this.serverPort = serverPort;
        this.quorum = quorum;
        this.stateSenderReplica = stateSenderReplica;
        View currentView = svController.getCurrentView();
        this.knownServerIps = new HashSet<>(currentView.getN());

        for (int process : currentView.getProcesses()) {
            String ip = currentView.getAddress(process).getAddress().getHostAddress();
            knownServerIps.add(ip);
        }
    }

    @Override
    public void run() {
        boolean usingLinearScheme = Configuration.getInstance().getVssScheme().equals("1");
        try (ServerSocket serverSocket = new ServerSocket()) {
            String myIp = svController.getStaticConf()
                    .getLocalAddress(svController.getStaticConf().getProcessId())
                    .getAddress().getHostAddress();
            serverSocket.bind(new InetSocketAddress(myIp, serverPort));
            logger.debug("Listening for blinded data on {}:{}",
                    serverSocket.getInetAddress().getHostAddress(), serverSocket.getLocalPort());
            int nReceivedStates = 0;
            boolean receivedFullState = false;
            while (nReceivedStates < quorum || !receivedFullState) {
                try (Socket client = serverSocket.accept();
                     ObjectInput in = new ObjectInputStream(client.getInputStream())) {
                    client.setKeepAlive(true);
                    client.setTcpNoDelay(true);

                    String clientIp = client.getInetAddress().getHostAddress();
                    if (!knownServerIps.contains(clientIp)) {
                        logger.debug("Received connection from unknown server with ip {}", clientIp);
                        continue;
                    }

                    long t1Total, t1CommonState, t1Commitments, t1BlindedShares;
                    long t2Total, t2CommonState, t2Commitments, t2BlindedShares;
                    long elapsedTotal = 0, elapsedCommonState = 0, elapsedCommitments = 0, elapsedBlindedShares = 0;

                    byte[] commonState = null;
                    byte[] commonStateHash = null;
                    byte[][] shares;
                    Commitment[] commitments = null;
                    byte[] commitmentsHash = null;

                    t1Total = System.nanoTime();
                    int pid = in.readInt();
                    t2Total = System.nanoTime();
                    elapsedTotal += t2Total - t1Total;

                    logger.debug("Going to receive blinded data from {}", pid);

                    //Reading common state
                    HashThread commonStateHashThread = null;
                    byte flag = (byte) in.read();
                    int size = in.readInt();
                    if (flag == 0) {
                        logger.debug("Going to receive {} bytes of common state", size);
                        commonState = new byte[size];
                        commonStateHashThread = new HashThread();
                        commonStateHashThread.setData(commonState);
                        commonStateHashThread.start();
                        int i = 0;
                        while (i < size) {
                            t1CommonState = System.nanoTime();
                            int received = in.read(commonState, i, size - i);
                            t2CommonState = System.nanoTime();
                            elapsedCommonState += t2CommonState - t1CommonState;
                            if (received > -1) {
                                commonStateHashThread.update(i, received);
                                i += received;
                            }
                        }
                        logger.debug("Received common state from {}", pid);
                        commonStateHashThread.update(-1, -1);
                    } else {
                        logger.debug("Going to receive common state hash");
                        commonStateHash = new byte[size];
                        t1CommonState = System.nanoTime();
                        in.readFully(commonStateHash);
                        t2CommonState = System.nanoTime();
                        elapsedCommonState += t2CommonState - t1CommonState;
                    }

                    //Trying to read commitments
                    HashThread commitmentsHashThread = null;
                    if (usingLinearScheme) {
                        flag = (byte) in.read();
                        if (flag == 0) {
                            t1Commitments = System.nanoTime();
                            int nCommitments = in.readInt();
                            t2Commitments = System.nanoTime();
                            elapsedCommitments += t2Commitments - t1Commitments;
                            logger.debug("Going to receive {} commitments from {}", nCommitments, pid);
                            commitments = new Commitment[nCommitments];

                            int totalCommitmentsArraySize = 4 * nCommitments;
                            byte[] commitmentsHashArray = new byte[totalCommitmentsArraySize];

                            commitmentsHashThread = new HashThread();
                            commitmentsHashThread.setData(commitmentsHashArray);
                            commitmentsHashThread.start();
                            int index = 0;
                            byte[] b;
                            for (int i = 0; i < nCommitments; i++) {
                                t1Commitments = System.nanoTime();
                                commitments[i] = Utils.readCommitment(in);
                                t2Commitments = System.nanoTime();
                                elapsedCommitments += t2Commitments - t1Commitments;
                                b = confidential.Utils.toBytes(commitments[i].consistentHash());
                                for (byte value : b) {
                                    commitmentsHashArray[index++] = value;
                                }
                                commitmentsHashThread.update(index - 4, 4);
                            }
                            commitmentsHashThread.update(-1, -1);
                        }
                    } else {
                        t1Commitments = System.nanoTime();
                        int nCommitments = in.readInt();
                        t2Commitments = System.nanoTime();
                        elapsedCommitments += t2Commitments - t1Commitments;
                        commitments = new Commitment[nCommitments];
                        for (int i = 0; i < nCommitments; i++) {
                            t1Commitments = System.nanoTime();
                            commitments[i] = Utils.readCommitment(in);
                            t2Commitments = System.nanoTime();
                            elapsedCommitments += t2Commitments - t1Commitments;
                        }
                    }


                    //Reading blinded shares
                    int nShares = in.readInt();
                    logger.debug("Going to receive {} shares from {}", nShares, pid);
                    shares = new byte[nShares][];
                    byte[] b;
                    for (int i = 0; i < nShares; i++) {
                        size = in.readInt();
                        b = new byte[size];
                        t1BlindedShares = System.nanoTime();
                        in.readFully(b);
                        t2BlindedShares = System.nanoTime();
                        elapsedBlindedShares += t2BlindedShares - t1BlindedShares;
                        shares[i] = b;
                    }

                    logger.debug("Received blinded state from {}", pid);

                    //Reading commitments
                    if (commitments == null) {
                        t1Commitments = System.nanoTime();
                        size = in.readInt();
                        t2Commitments = System.nanoTime();
                        elapsedCommitments += t2Commitments - t1Commitments;

                        commitmentsHash = new byte[size];

                        t1Commitments = System.nanoTime();
                        in.readFully(commitmentsHash);
                        t2Commitments = System.nanoTime();
                        elapsedCommitments += t2Commitments - t1Commitments;
                    } else if (commitmentsHashThread != null) {
                        commitmentsHash = commitmentsHashThread.getHash();
                    }
                    if (commonStateHashThread != null) {
                        commonStateHash = commonStateHashThread.getHash();
                    }

                    elapsedTotal += elapsedCommonState + elapsedCommitments + elapsedBlindedShares;

                    logger.info("Took {} ms to receive common state from {}", elapsedCommonState / 1_000_000.0, pid);
                    logger.info("Took {} ms to receive commitments from {}", elapsedCommitments / 1_000_000.0, pid);
                    logger.info("Took {} ms to receive blinded shares from {}", elapsedBlindedShares / 1_000_000.0, pid);
                    logger.info("Took {} ms to receive state from {} (total)", elapsedTotal / 1_000_000.0, pid);
                    blindedStateHandler.deliverBlindedData(pid, shares, commonState, commonStateHash,
                            commitments, commitmentsHash);
                    if (pid == stateSenderReplica)
                        receivedFullState = true;
                    nReceivedStates++;
                } catch (NoSuchAlgorithmException e) {
                    logger.error("Failed to create hash thread.", e);
                } catch (ClassNotFoundException e) {
                    logger.error("Failed to read commitments.", e);
                } catch (IOException e) {
                    logger.error("Failed to receive data", e);
                }
            }
        } catch (IOException e) {
            logger.error("Failed to initialize server socket.", e);
        }
        logger.debug("Exiting blinded data receiver thread");
    }
}
