package confidential.statemanagement;

import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class RecoverySMMessage extends SMMessage {
    private int sequenceNumber;
    private RecoveryApplicationState recoveryState;

    public RecoverySMMessage() {
        super();
    }

    public RecoverySMMessage(int sender, int cid, int type, RecoveryApplicationState recoveryState, View view,
                             int regency, int leader, int sequenceNumber) {
        super(sender, cid, type, null, view, regency, leader);
        this.sequenceNumber = sequenceNumber;
        this.recoveryState = recoveryState;
    }

    public RecoveryApplicationState getRecoveryState() {
        return recoveryState;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(sequenceNumber);
        recoveryState.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        sequenceNumber = in.readInt();
        recoveryState = new RecoveryApplicationState();
        recoveryState.readExternal(in);
    }
}
