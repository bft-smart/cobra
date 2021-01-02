package confidential.statemanagement;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.reconfiguration.views.View;
import confidential.Utils;
import confidential.statemanagement.utils.HashThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Robin
 */
public class RecoveryPublicStateReceiver extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private StateRecoveryHandler stateRecoveryHandler;
    private Set<String> knownServersIps;
    private ServerSocket serverSocket;

    RecoveryPublicStateReceiver(StateRecoveryHandler stateRecoveryHandler,
                                ServerViewController svController, int serverPort) throws IOException {
        super("RecoveryStateReceiver");
        this.stateRecoveryHandler = stateRecoveryHandler;
        this.serverSocket = ServerSocketFactory.getDefault().createServerSocket(serverPort);
        View currentView = svController.getCurrentView();
        this.knownServersIps = new HashSet<>(currentView.getN());

        for (int process : currentView.getProcesses()) {
            String ip = currentView.getAddress(process).getAddress().getHostAddress();
            knownServersIps.add(ip);
        }
    }

    @Override
    public void run() {
        while (true) {
            try (Socket client = serverSocket.accept()) {
                client.setKeepAlive(true);
                client.setTcpNoDelay(true);

                String clientIp = client.getInetAddress().getHostAddress();

                if (!knownServersIps.contains(clientIp)) {
                    logger.debug("Received connection from unknown server with ip {}", clientIp);
                    continue;
                }
                BufferedInputStream in = new BufferedInputStream(client.getInputStream());
                int pid = Utils.toNumber(Utils.readNBytes(4, in));
                logger.debug("Received un-secure connection from {}", pid);

                long t1, t2;
                byte[] publicState = null;
                byte[] publicStateHash;
                t1 = System.nanoTime();
                int commitmentBytes = Utils.toNumber(Utils.readNBytes(4, in));
                byte[] commitments = Utils.readNBytes(commitmentBytes, in);
                t2 = System.nanoTime();
                logger.info("Took {} ms to receive commitments of size {} from {}",
                        (t2 - t1) / 1_000_000.0, commitmentBytes, pid);

                t1 = System.nanoTime();
                if (in.read() == 1) {
                    int nCommonStateBytes = Utils.toNumber(Utils.readNBytes(4, in));
                    publicState = new byte[nCommonStateBytes];
                    int i = 0;
                    HashThread hashThread = new HashThread();
                    hashThread.setData(publicState);
                    hashThread.start();

                    while (i < nCommonStateBytes) {
                        int received = in.read(publicState, i, nCommonStateBytes - i);
                        if (received < 1)
                            logger.info("-->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>Received " +
                                    "number: {}", received);
                        hashThread.update(i, received);
                        i += received;
                    }
                    hashThread.update(-1, -1);
                    publicStateHash = hashThread.getHash();
                    //byte[] tpublicStateHash = TOMUtil.computeHash(publicState);
                    //logger.info("delete->>>>RecPSReceiver>>>>Test hash: {}",
                    //        tpublicStateHash);
                    //publicStateHash = tpublicStateHash;
                } else {
                    publicStateHash = Utils.readNBytes(Utils.toNumber(Utils.readNBytes(4, in)), in);
                }

                t2 = System.nanoTime();
                logger.info("Took {} ms to receive public state from {} with hash {}", (t2 - t1) / 1_000_000.0, pid,
                        Arrays.toString(publicStateHash));
                in.close();

                stateRecoveryHandler.deliverPublicState(pid, publicState,
                        publicStateHash, commitments);
            } catch (IOException e) {
                break;
            } catch (NoSuchAlgorithmException e) {
                logger.error("Failed to initialize Hash Thread.", e);
                break;
            }
        }
        logger.debug("Exiting public state receiver thread");
    }

    @Override
    public void interrupt() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            logger.error("Failed to close socket");
        }
        super.interrupt();
    }
}
