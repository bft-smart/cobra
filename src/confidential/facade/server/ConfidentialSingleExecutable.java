package confidential.facade.server;

import bftsmart.tom.MessageContext;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.statemanagement.ConfidentialSnapshot;

/**
 * @author Robin
 */
public interface ConfidentialSingleExecutable {
    ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx);

    ConfidentialMessage appExecuteUnordered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx);

    ConfidentialSnapshot getConfidentialSnapshot();

    void installConfidentialSnapshot(ConfidentialSnapshot snapshot);
}
