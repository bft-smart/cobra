package confidential.demo.counter.server;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import confidential.ConfidentialMessage;
import confidential.server.ConfidentialRecoverable;
import confidential.statemanagement.ConfidentialSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.VerifiableShare;

import java.util.concurrent.atomic.AtomicInteger;

public class CounterServer extends ConfidentialRecoverable {
    private Logger logger = LoggerFactory.getLogger("demo");
    private AtomicInteger counter;


    public CounterServer(int processId) {
        super(processId);
        counter = new AtomicInteger();
        new ServiceReplica(processId, this, this);
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx) {
        int i = counter.incrementAndGet();
        logger.debug("Ordered - Counter: {} Client: {}", i, msgCtx.getSender());
        return new ConfidentialMessage(String.valueOf(i).getBytes());
    }

    @Override
    public ConfidentialMessage appExecuteUnordered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx) {
        int i = counter.incrementAndGet();
        logger.debug("Unordered - Counter: {} Client: {}", i, msgCtx.getSender());
        return new ConfidentialMessage(String.valueOf(i).getBytes());
    }

    @Override
    public ConfidentialSnapshot getConfidentialSnapshot() {
        return new ConfidentialSnapshot(String.valueOf(counter.get()).getBytes());
    }

    @Override
    public void installConfidentialSnapshot(ConfidentialSnapshot snapshot) {
        int c = Integer.parseInt(new String(snapshot.getPlainData()));
        logger.debug("Installing state: {}", c);
        counter = new AtomicInteger(c);
    }
}
