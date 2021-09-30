package confidential.interServersCommunication;

import bftsmart.communication.server.ServersCommunicationLayer;
import bftsmart.reconfiguration.ServerViewController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Simplified version of BFT-SMaRT's bftsmart.communication.server.ServerConnection.java
 */
public class Connection {
    private final Logger logger = LoggerFactory.getLogger("communication");
    private static final long POOL_TIME = 5000;
    private final boolean useSenderThread;
    private final LinkedBlockingQueue<byte[]> outQueue;
    private final ServerViewController svController;
    private final int remoteId;
    private Lock sendLock;
    private SSLSocket socket;
    private DataOutputStream socketOutStream;
    private DataInputStream socketInStream;
    private boolean doWork;
    private final Lock connectLock;
    private final ReceiverThread receiverThread;
    private KeyStore ks;
    private FileInputStream fis;
    private SSLSocketFactory socketFactory;
    private static final String SECRET = "MySeCreT_2hMOygBwY";

    public Connection(ServerViewController svController, int remoteId, SSLSocket socket,
                      LinkedBlockingQueue<InternalMessage> inQueue) {
        this.useSenderThread = svController.getStaticConf().isUseSenderThread();
        this.outQueue = new LinkedBlockingQueue<>(svController.getStaticConf().getOutQueueSize());
        this.svController = svController;
        this.remoteId = remoteId;
        this.socket = socket;
        this.doWork = true;
        this.connectLock = new ReentrantLock(true);

        if (isToConnect()) {
            sslTLSCreateConnection();
        }
        if (this.socket != null) {
            try {
                socketOutStream = new DataOutputStream(this.socket.getOutputStream());
                socketInStream = new DataInputStream(this.socket.getInputStream());
            } catch (IOException e) {
                throw new IllegalStateException("Error while creating connection to " + remoteId, e);
            }
        }

        if (useSenderThread) {
            logger.debug("Using sender thread for {}", remoteId);
            new SenderThread(remoteId, outQueue, this)
                    .start();
        } else {
            sendLock = new ReentrantLock(true);
        }

        receiverThread = new ReceiverThread(remoteId, inQueue, this.socket, socketInStream, this);
        receiverThread.start();
    }

    public void send(byte[] data) {
        if (useSenderThread) {
            logger.debug("Queue message for {}", remoteId);
            if (!outQueue.offer(data)) {
                logger.debug("Out queue for {} is full (message discarded)", remoteId);
            }
        } else {
            sendLock.lock();
            sendBytes(data);
            sendLock.unlock();
        }
    }

    public void sendBytes(byte[] messageData) {
        boolean abort = false;
        do {
            if (abort) {
                return; // if there is a need to reconnect, abort this method
            }
            if (socket != null && socketOutStream != null) {
                try {
                    logger.debug("Sending data to {}", remoteId);
                    // do an extra copy of the data to be sent, but on a single out stream write
                    byte[] data = new byte[5 + messageData.length];// without MAC
                    int value = messageData.length;

                    System.arraycopy(new byte[] { (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8),
                            (byte) value }, 0, data, 0, 4);
                    System.arraycopy(messageData, 0, data, 4, messageData.length);
                    System.arraycopy(new byte[] { (byte) 0 }, 0, data, 4 + messageData.length, 1);

                    socketOutStream.write(data);

                    return;
                } catch (IOException ex) {
                    closeSocket();
                    waitAndConnect();
                    abort = true;
                }
            } else {
                waitAndConnect();
                abort = true;
            }
        } while (doWork);
    }

    public boolean isDoingWork() {
        return doWork;
    }

    public void shutdown() {
        logger.debug("SHUTDOWN for {}", remoteId);

        doWork = false;
        closeSocket();
    }

    private boolean isToConnect() {
        return svController.isInCurrentView() && svController.getStaticConf().getProcessId() > remoteId;
    }

    public void closeSocket() {
        connectLock.lock();

        if (socket != null) {
            try {
                socketOutStream.flush();
                socket.close();
            } catch (IOException ex) {
                logger.debug("Error closing socket to "+remoteId);
            } catch (NullPointerException npe) {
                logger.debug("Socket already closed");
            }

            socket = null;
            socketOutStream = null;
            socketInStream = null;
        }

        connectLock.unlock();
    }

    public void waitAndConnect() {
        if (doWork) {
            try {
                Thread.sleep(POOL_TIME);
            } catch (InterruptedException ignored) { }

            outQueue.clear();
            reconnect(null);
        }
    }

    protected void reconnect(SSLSocket newSocket) {
        connectLock.lock();

        if (socket == null || !socket.isConnected()) {
            if (isToConnect()) {
                logger.debug("Reconnecting to {}", remoteId);
                sslTLSCreateConnection();
            } else {
                socket = newSocket;
            }

            if (socket != null) {
                try {
                    socketOutStream = new DataOutputStream(socket.getOutputStream());
                    socketInStream = new DataInputStream(socket.getInputStream());
                    receiverThread.updateConnection(socket, socketInStream);
                } catch (IOException ex) {
                    logger.error("Failed to authenticate to replica", ex);
                }
            }
        } else {
            logger.debug("Socket is already connected to {}", remoteId);
        }

        connectLock.unlock();
    }

    public void sslTLSCreateConnection() {

        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        try {
            fis = new FileInputStream("config/keysSSL_TLS/" + svController.getStaticConf().getSSLTLSKeyStore());
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fis, SECRET.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            logger.error("SSL connection error.",e);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    logger.error("IO error.",e);
                }
            }
        }
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, SECRET.toCharArray());

            TrustManagerFactory trustMgrFactory = TrustManagerFactory.getInstance(algorithm);
            trustMgrFactory.init(ks);
            SSLContext context = SSLContext.getInstance(svController.getStaticConf().getSSLTLSProtocolVersion());
            context.init(kmf.getKeyManagers(), trustMgrFactory.getTrustManagers(), new SecureRandom());
            socketFactory = context.getSocketFactory();

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyManagementException e) {
            logger.error("SSL connection error.",e);
        }
        // Create the connection.
        try {
            int port = svController.getStaticConf().getServerToServerPort(remoteId)
                    + 1;
            logger.debug("Connecting to {}", remoteId);
            this.socket = (SSLSocket) socketFactory.createSocket(svController.getStaticConf().getHost(remoteId),
                    port);
            this.socket.setKeepAlive(true);
            this.socket.setTcpNoDelay(true);
            this.socket.setEnabledCipherSuites(svController.getStaticConf().getEnabledCiphers());

            this.socket.addHandshakeCompletedListener(event -> logger.info("SSL/TLS handshake complete!, Id:{}" + "  ## CipherSuite: {}.", remoteId,
                    event.getCipherSuite()));

            this.socket.startHandshake();

            ServersCommunicationLayer.setSSLSocketOptions(this.socket);
            new DataOutputStream(this.socket.getOutputStream())
                    .writeInt(svController.getStaticConf().getProcessId());

        } catch (SocketException e) {
            logger.error("Connection refused (SocketException)");
            // e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
