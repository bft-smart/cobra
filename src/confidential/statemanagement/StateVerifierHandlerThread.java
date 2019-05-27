package confidential.statemanagement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class StateVerifierHandlerThread implements Runnable {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private BlockingQueue<RecoverySMMessage> states;

    public StateVerifierHandlerThread() {
        states = new LinkedBlockingQueue<>();
    }


    public void addStateForVerification(RecoverySMMessage state) {
        try {
            states.put(state);
        } catch (InterruptedException e) {
            logger.error("Failed to out state for verification from {}", state.getSender(), e);
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                RecoverySMMessage state = states.take();
            } catch (InterruptedException e) {
                break;
            }
        }
        logger.debug("Exiting state verifier handler thread");
    }
}
