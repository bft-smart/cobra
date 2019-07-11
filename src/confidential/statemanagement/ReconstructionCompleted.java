package confidential.statemanagement;

import bftsmart.tom.server.defaultservices.DefaultApplicationState;

public interface ReconstructionCompleted {
    void onReconstructionCompleted(DefaultApplicationState recoveredState);
}
