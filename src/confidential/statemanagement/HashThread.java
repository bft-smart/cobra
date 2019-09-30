package confidential.statemanagement;

import bftsmart.tom.util.TOMUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author Robin
 */
public class HashThread extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private MessageDigest digest;
    private Lock lock;
    private BlockingQueue<Pair> offsets;
    private byte[] data;

    HashThread() throws NoSuchAlgorithmException {
        super("Hash Thread");
        this.digest = TOMUtil.getHashEngine();
        this.lock = new ReentrantLock();
        this.offsets = new LinkedBlockingDeque<>();
    }

    void setData(byte[] data) {
        this.data = data;
    }

    byte[] getHash() {
        lock.lock();
        byte[] result = digest.digest();
        lock.unlock();
        return result;
    }

    public void update(int offset, int len) {
        try {
            offsets.put(new Pair(offset, len));
        } catch (InterruptedException e) {
            logger.error("Failed to add offset to queue.", e);
        }
    }

    @Override
    public void run() {
        lock.lock();
        while (true) {
            try {
                Pair offset = offsets.take();
                if (offset.offset == -1)
                    break;
                digest.update(data, offset.offset, offset.len);
            } catch (InterruptedException e) {
                logger.error("Failed to take offset from queue.", e);
            }
        }
        lock.unlock();
        logger.debug("Exiting Hash Thread");
    }

    private static class Pair {
        private int offset;
        private int len;

        Pair(int offset, int len) {
            this.offset = offset;
            this.len = len;
        }
    }
}
