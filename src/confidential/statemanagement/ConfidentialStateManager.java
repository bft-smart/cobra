package confidential.statemanagement;

import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfidentialStateManager extends StateManager {
    private Logger logger = LoggerFactory.getLogger("confidential");

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
