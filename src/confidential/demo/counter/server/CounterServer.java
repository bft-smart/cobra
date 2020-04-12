package confidential.demo.counter.server;

import bftsmart.tom.MessageContext;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.facade.server.ConfidentialServerFacade;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.statemanagement.ConfidentialSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

public class CounterServer implements ConfidentialSingleExecutable {
    private Logger logger = LoggerFactory.getLogger("demo");
    private AtomicInteger counter;


    CounterServer(int processId) {
        counter = new AtomicInteger();
        new ConfidentialServerFacade(processId, this);
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        int i = counter.incrementAndGet();
        logger.debug("Ordered - Counter: {} Client: {} CID: {} OpId: {}", i, msgCtx.getSender(),
                msgCtx.getConsensusId(), msgCtx.getOperationId());
        return new ConfidentialMessage(String.valueOf(i).getBytes());
    }

    @Override
    public ConfidentialMessage appExecuteUnordered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        int i = counter.incrementAndGet();
        logger.debug("Unordered - Counter: {} Client: {} - CID: {} OpId: {}", i, msgCtx.getSender(),
                msgCtx.getConsensusId(), msgCtx.getOperationId());
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
