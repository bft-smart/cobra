package confidential.statemanagement;

import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class DefaultSMMessage extends SMMessage {
    private int stateSenderReplica;

    public DefaultSMMessage() {}

    protected DefaultSMMessage(int sender, int cid, int type, ApplicationState state, View view, int regency,
                               int leader, int stateSenderReplica) {
        super(sender, cid, type, state, view, regency, leader);
        this.stateSenderReplica = stateSenderReplica;
    }

    public int getStateSenderReplica() {
        return stateSenderReplica;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(stateSenderReplica);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        stateSenderReplica = in.readInt();
    }
}
