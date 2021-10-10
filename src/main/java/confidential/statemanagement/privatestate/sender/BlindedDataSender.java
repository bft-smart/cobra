package confidential.statemanagement.privatestate.sender;

import confidential.Configuration;
import confidential.statemanagement.utils.HashThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.Utils;
import vss.commitment.Commitment;

import javax.net.SocketFactory;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class BlindedDataSender extends Thread {
    private final Logger logger = LoggerFactory.getLogger("state_transfer");
    private final int pid;
    private final String receiverServersIp;
    private final int receiverServerPort;
    private final boolean iAmStateSender;
    private Socket connection;
    private final Lock lock;
    private final Condition waitingSharesCondition;
    private final Condition waitingCommonStateCondition;
    private BlindedShares blindedShares;
    private byte[] commonState;
    private byte[] commonStateHash;


    public BlindedDataSender(int pid, String receiverServersIp, int receiverServerPort, boolean iAmStateSender) {
        super("Blinded Data Sender Thread for " + receiverServersIp + ":" + receiverServerPort);
        this.pid = pid;
        this.receiverServersIp = receiverServersIp;
        this.receiverServerPort = receiverServerPort;
        this.iAmStateSender = iAmStateSender;
        this.lock = new ReentrantLock(true);
        this.waitingSharesCondition = lock.newCondition();
        this.waitingCommonStateCondition = lock.newCondition();
    }

    public void setBlindedShares(BlindedShares blindedShares) {
        lock.lock();
        this.blindedShares = blindedShares;
        waitingSharesCondition.signal();
        lock.unlock();
    }

    public void setCommonState(byte[] commonState, byte[] commonStateHash) {
        lock.lock();
        this.commonState = commonState;
        this.commonStateHash = commonStateHash;
        waitingCommonStateCondition.signal();
        lock.unlock();
    }

    @Override
    public void run() {
        boolean usingLinearScheme = Configuration.getInstance().getVssScheme().equals("1");
        try {
            //Waiting for common state
            lock.lock();
            if (commonState == null && commonStateHash == null) {
                waitingCommonStateCondition.await();
            }
            lock.unlock();

            //connecting
            logger.debug("Connecting to {}:{}", receiverServersIp, receiverServerPort);
            connection = SocketFactory.getDefault().createSocket(receiverServersIp, receiverServerPort);
            try (ObjectOutput out = new ObjectOutputStream(connection.getOutputStream())) {
                connection.setKeepAlive(true);
                connection.setTcpNoDelay(true);
                out.writeInt(pid);
                //Sending common state
                if (iAmStateSender) {
                    logger.info("Sending {} bytes of common state", commonState.length);
                    out.write(0); //sending full state
                    out.writeInt(commonState.length);
                    out.write(commonState);
                } else {
                    logger.debug("Sending common state hash");
                    out.write(1); //sending hash
                    out.writeInt(commonStateHash.length);
                    out.write(commonStateHash);
                }
                out.flush();
                logger.debug("Sent common state");

                //Waiting for blinded shares
                lock.lock();
                if (blindedShares == null) {
                    waitingSharesCondition.await();
                }
                lock.unlock();
                logger.debug("Received blinded shares");
                //Computing commitments hash
                HashThread commitmentsHashThread = null;
                Commitment[] commitments = blindedShares.getCommitment();
                if (usingLinearScheme) {
                    if (iAmStateSender) {
                        logger.info("Sending {} commitments", commitments.length);
                        out.write(0);//3 - sending commitments first
                        out.writeInt(commitments.length);
                        for (Commitment commitment : commitments) {
                            Utils.writeCommitment(commitment, out);
                        }
                        out.flush();
                    } else {
                        out.write(1);//3 - not sending commitments first
                        int totalCommitmentsArraySize = 4 * commitments.length;
                        byte[] commitmentsHashArray = new byte[totalCommitmentsArraySize];
                        commitmentsHashThread = new HashThread();
                        commitmentsHashThread.setData(commitmentsHashArray);
                        commitmentsHashThread.start();

                        int index = 0;
                        byte[] b;
                        for (Commitment commitment : commitments) {
                            b = confidential.Utils.toBytes(commitment.consistentHash());
                            for (byte value : b) {
                                commitmentsHashArray[index++] = value;
                            }
                            commitmentsHashThread.update(index - 4, 4);
                        }
                    }
                } else {
                    logger.info("Sending {} commitments", commitments.length);
                    out.writeInt(commitments.length);
                    for (Commitment commitment : commitments) {
                        Utils.writeCommitment(commitment, out);
                    }
                    out.flush();
                }

                //Sending blinded shares
                long totalBytes = 0;
                byte[][] shares = blindedShares.getShare();
                logger.info("Sending {} blinded shares", shares.length);
                out.writeInt(shares.length);
                for (byte[] blindedShare : shares) {
                    out.writeInt(blindedShare.length);
                    out.write(blindedShare);
                    totalBytes += blindedShare.length;
                }
                out.flush();
                logger.info("Sent {} bytes of blinded shares", totalBytes);

                //Sending commitments
                if (usingLinearScheme && commitmentsHashThread != null) {
                    logger.debug("Sending commitments hash");
                    commitmentsHashThread.update(-1, -1);
                    byte[] commitmentsHash = commitmentsHashThread.getHash();
                    out.writeInt(commitmentsHash.length);
                    out.write(commitmentsHash);
                }
                out.flush();
            }
            connection.close();
        } catch (SocketException | InterruptedException ignored) {
        } catch (IOException | NoSuchAlgorithmException e) {
            logger.error("Failed to send data to {}:{}", receiverServersIp, receiverServerPort, e);
        }

        logger.debug("Exiting blinded data sender for {}:{}", receiverServersIp, receiverServerPort);
    }

    public void shutdown() {
        try {
            if (connection.isConnected())
                connection.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
