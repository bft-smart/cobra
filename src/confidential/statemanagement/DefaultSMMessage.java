package confidential.statemanagement;

import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;

public class DefaultSMMessage extends SMMessage {
    private int stateSenderReplica;

    protected DefaultSMMessage(int sender, int cid, int type, ApplicationState state, View view, int regency,
                     int leader, int stateSenderReplica) {
        super(sender, cid, type, state, view, regency, leader);
        this.stateSenderReplica = stateSenderReplica;
    }

    public int getStateSenderReplica() {
        return stateSenderReplica;
    }
}
