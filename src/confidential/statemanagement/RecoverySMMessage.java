package confidential.statemanagement;

import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class RecoverySMMessage extends SMMessage {
    private int sequenceNumber;

    public RecoverySMMessage() {
        super();
    }

    public RecoverySMMessage(int sender, int cid, int type, ApplicationState state, View view, int regency,
                                int leader, int sequenceNumber) {
        super(sender, cid, type, state, view, regency, leader);
        this.sequenceNumber = sequenceNumber;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(sequenceNumber);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        sequenceNumber = in.readInt();
    }
}
