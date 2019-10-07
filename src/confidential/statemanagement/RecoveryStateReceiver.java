package confidential.statemanagement;

import bftsmart.reconfiguration.ServerViewController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitments;
import vss.secretsharing.Share;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * @author Robin
 */
public class RecoveryStateReceiver extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private static final String SECRET = "MySeCreT_2hMOygBwY";
    private SSLSocketFactory socketFactory;
    private StateRecoveryHandler stateRecoveryHandler;
    private BlockingQueue<RecoveryStateServerSMMessage> recoveryHelperServers;
    private ServerViewController svController;

    RecoveryStateReceiver(StateRecoveryHandler stateRecoveryHandler,
                          ServerViewController svController) throws IOException, UnrecoverableKeyException,
            CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        super("RecoveryStateReceiver");
        this.stateRecoveryHandler = stateRecoveryHandler;
        this.svController = svController;
        this.recoveryHelperServers = new LinkedBlockingDeque<>();
        this.socketFactory = getSSLSocketFactory(svController);
    }

    private SSLSocketFactory getSSLSocketFactory(ServerViewController svController) throws CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        try (FileInputStream fis = new FileInputStream("config/keysSSL_TLS/" +
                svController.getStaticConf().getSSLTLSKeyStore())) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fis, SECRET.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, SECRET.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init(ks);

            SSLContext context = SSLContext.getInstance(svController.getStaticConf().getSSLTLSProtocolVersion());
            context.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            return context.getSocketFactory();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException
                | UnrecoverableKeyException | KeyManagementException e) {
            logger.error("Failed to initialize SSL attributes", e);
            throw e;
        }
    }

    void addRecoveryStateMessage(RecoveryStateServerSMMessage msg) {
        try {
            recoveryHelperServers.put(msg);
        } catch (InterruptedException e) {
            logger.error("Failed to add recovery state message", e);
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                RecoveryStateServerSMMessage serverInfo = recoveryHelperServers.take();
                logger.info("Connecting to {} to ask recovery state ({}:{})", serverInfo.getSender(),
                        serverInfo.getServerIp(), serverInfo.getServerPort());
                SSLSocket socket = (SSLSocket) socketFactory.createSocket(
                        serverInfo.getServerIp(), serverInfo.getServerPort());
                socket.setKeepAlive(true);
                socket.setTcpNoDelay(true);
                socket.setEnabledCipherSuites(svController.getStaticConf().getEnabledCiphers());

                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

                long t1 = System.nanoTime();
                byte[] recoveryStateWithoutCommonState = new byte[in.readInt()];
                in.readFully(recoveryStateWithoutCommonState);
                long t2 = System.nanoTime();
                logger.info("Took {} ms to receive recovery state without common state from {}",
                        (t2 - t1) / 1_000_000.0, serverInfo.getSender());

                byte[] commonState = null;
                byte[] commonStateHash;

                t1 = System.nanoTime();
                if (in.readBoolean()) {
                    int nCommonStateBytes = in.readInt();
                    commonState = new byte[nCommonStateBytes];
                    int i = 0;
                    HashThread hashThread = new HashThread();
                    hashThread.setData(commonState);
                    hashThread.start();

                    while (i < nCommonStateBytes) {
                        int received = in.read(commonState, i, nCommonStateBytes - i);
                        hashThread.update(i, received);
                        i += received;
                    }
                    hashThread.update(-1, -1);
                    commonStateHash = hashThread.getHash();

                } else {
                    commonStateHash = new byte[in.readInt()];
                    in.readFully(commonStateHash);
                }

                t2 = System.nanoTime();

                logger.info("Took {} ms to receive common state from {}",
                        (t2 - t1) / 1_000_000.0, serverInfo.getSender());
                socket.close();

                t1 = System.nanoTime();
                RecoveryApplicationState recoveryApplicationState = reconstructRecoveryState(serverInfo.getSender(),
                        recoveryStateWithoutCommonState, commonState, commonStateHash);
                t2 = System.nanoTime();
                logger.debug("Took {} ms to reconstruct recovery state from {}", (t2 - t1) / 1_000_000.0,
                        serverInfo.getSender());
                stateRecoveryHandler.deliverRecoveryStateMessage(recoveryApplicationState);
            } catch (InterruptedException e) {
                break;
            } catch (IOException e) {
                logger.error("Failed to receive state.", e);
            } catch (NoSuchAlgorithmException e) {
                logger.error("Failed to initialize Hash Thread.", e);
            }
        }
        logger.debug("Exiting recovery state receiver thread");
    }

    private RecoveryApplicationState reconstructRecoveryState(int from, byte[] stateWithoutCommonState,
                                                              byte[] commonState, byte[] commonStateHash) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(stateWithoutCommonState);
             ObjectInput in = new ObjectInputStream(bis)) {
            Commitments transferPolynomialCommitments = new Commitments();
            transferPolynomialCommitments.readExternal(in);
            int lastCheckpointCID = in.readInt();
            int lastCID = in.readInt();
            int pid = in.readInt();
            int nShares = in.readInt();
            LinkedList<Share> shares = new LinkedList<>();
            while (nShares-- > 0) {
                Share share = new Share();
                share.readExternal(in);
                shares.add(share);
            }

            return new RecoveryApplicationState(
                    commonState,
                    commonStateHash,
                    shares,
                    lastCheckpointCID,
                    lastCID,
                    pid,
                    transferPolynomialCommitments
            );
        } catch (IOException e) {
            logger.debug("Failed to reconstruct recovery state from {}", from);
            return null;
        }
    }
}
