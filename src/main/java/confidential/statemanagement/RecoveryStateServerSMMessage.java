package confidential.statemanagement;

import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.SMMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author Robin
 */
public class RecoveryStateServerSMMessage extends SMMessage {
    private int sequenceNumber;

    public RecoveryStateServerSMMessage() {
        super();
    }

    public RecoveryStateServerSMMessage(int sender, int cid, int type, View view, int regency, int leader,
                                        int sequenceNumber) {
        super(sender, cid, type, null, view, regency, leader);
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
