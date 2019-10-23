package confidential.statemanagement;

import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class DefaultSMMessage extends SMMessage {
    private int stateSenderReplica;
    private int serverPort;

    public DefaultSMMessage() {}

    protected DefaultSMMessage(int sender, int cid, int type, ApplicationState state, View view, int regency,
                               int leader, int stateSenderReplica, int serverPort) {
        super(sender, cid, type, state, view, regency, leader);
        this.stateSenderReplica = stateSenderReplica;
        this.serverPort = serverPort;
    }

    public int getStateSenderReplica() {
        return stateSenderReplica;
    }

    public int getServerPort() {
        return serverPort;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(stateSenderReplica);
        out.writeInt(serverPort);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        stateSenderReplica = in.readInt();
        serverPort = in.readInt();
    }
}
