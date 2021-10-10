package confidential.facade.server;

import bftsmart.tom.MessageContext;
import confidential.ConfidentialMessage;
import confidential.statemanagement.ConfidentialSnapshot;
import vss.secretsharing.VerifiableShare;

/**
 * @author Robin
 */
public interface ConfidentialSingleExecutable {
    ConfidentialMessage appExecuteOrdered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx);

    ConfidentialMessage appExecuteUnordered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx);

    ConfidentialSnapshot getConfidentialSnapshot();

    void installConfidentialSnapshot(ConfidentialSnapshot snapshot);
}
