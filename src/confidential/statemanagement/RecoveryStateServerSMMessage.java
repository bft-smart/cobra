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
    private String serverIp;
    private int serverPort;

    public RecoveryStateServerSMMessage() {
        super();
    }

    public RecoveryStateServerSMMessage(int sender, int cid, int type, View view, int regency, int leader,
                                        int sequenceNumber, String serverIp, int serverPort) {
        super(sender, cid, type, null, view, regency, leader);
        this.sequenceNumber = sequenceNumber;
        this.serverIp = serverIp;
        this.serverPort = serverPort;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public int getServerPort() {
        return serverPort;
    }

    public String getServerIp() {
        return serverIp;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(sequenceNumber);
        out.writeUTF(serverIp);
        out.writeInt(serverPort);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        sequenceNumber = in.readInt();
        serverIp = in.readUTF();
        serverPort = in.readInt();
    }
}
