package confidential.polynomial;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class PolynomialMessage implements Externalizable {
    private int id;
    private int sender;
    private int viewId;
    private int leader;
    private int[] viewMembers;

    public PolynomialMessage() {}

    public PolynomialMessage(int id, int sender, int viewId, int leader, int[] viewMembers) {
        this.id = id;
        this.sender = sender;
        this.viewId = viewId;
        this.leader = leader;
        this.viewMembers = viewMembers;
    }

    public int getId() {
        return id;
    }

    public int getSender() {
        return sender;
    }

    public int getViewId() {
        return viewId;
    }

    public int getLeader() {
        return leader;
    }

    public int[] getViewMembers() {
        return viewMembers;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(id);
        out.writeInt(sender);
        out.writeInt(viewId);
        out.writeInt(leader);
        out.writeInt(viewMembers.length);
        for (int m : viewMembers)
            out.writeInt(m);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        id = in.readInt();
        sender = in.readInt();
        viewId = in.readInt();
        leader = in.readInt();
        viewMembers = new int[in.readInt()];
        for (int i = 0; i < viewMembers.length; i++)
            viewMembers[i] = in.readInt();
    }
}
