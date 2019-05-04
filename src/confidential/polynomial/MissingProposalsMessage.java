package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class MissingProposalsMessage extends PolynomialMessage {
    private ProposalMessage[] missingProposals;

    public MissingProposalsMessage() {}

    public MissingProposalsMessage(int id, int sender, int viewId, int leader, int[] viewMembers, ProposalMessage[] missingProposals) {
        super(id, sender, viewId, leader, viewMembers);
        this.missingProposals = missingProposals;
    }

    public ProposalMessage[] getMissingProposals() {
        return missingProposals;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(missingProposals.length);
        for (ProposalMessage missingProposal : missingProposals) {
            missingProposal.writeExternal(out);
        }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        super.readExternal(in);
        int len = in.readInt();
        missingProposals = new ProposalMessage[len];
        for (int i = 0; i < len; i++) {
            ProposalMessage proposal = new ProposalMessage();
            proposal.readExternal(in);
            missingProposals[i] = proposal;
        }
    }
}
