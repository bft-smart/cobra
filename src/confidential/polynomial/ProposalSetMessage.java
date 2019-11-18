package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class ProposalSetMessage extends PolynomialMessage {
    private int[] receivedNodes;
    private byte[][] receivedProposals;//cryptographic hashes

    public ProposalSetMessage() {}

    public ProposalSetMessage(int id, int sender, int[] receivedNodes, byte[][] receivedProposals) {
        super(id, sender);
        this.receivedNodes = receivedNodes;
        this.receivedProposals = receivedProposals;
    }

    public int[] getReceivedNodes() {
        return receivedNodes;
    }

    public byte[][] getReceivedProposals() {
        return receivedProposals;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(receivedNodes.length);
        for (int receivedNode : receivedNodes) {
            out.writeInt(receivedNode);
        }

        out.writeInt(receivedProposals[0].length);
        for (byte[] receivedProposal : receivedProposals) {
            out.write(receivedProposal);
        }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        int len = in.readInt();
        receivedNodes = new int[len];
        receivedProposals = new byte[len][];
        for (int i = 0; i < receivedNodes.length; i++) {
            receivedNodes[i] = in.readInt();
        }

        len = in.readInt();
        for (int i = 0; i < receivedProposals.length; i++) {
            byte[] b = new byte[len];
            in.readFully(b);
            receivedProposals[i] = b;
        }
    }
}
