package confidential.statemanagement;

import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.StateManager;

public class ConfidentialStateManager extends StateManager {
    @Override
    protected void requestState() {

    }

    @Override
    public void stateTimeout() {

    }

    @Override
    public void SMRequestDeliver(SMMessage msg, boolean isBFT) {

    }

    @Override
    public void SMReplyDeliver(SMMessage msg, boolean isBFT) {

    }
}
