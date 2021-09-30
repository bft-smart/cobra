package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class MissingProposalsMessage extends PolynomialMessage {
    private ProposalMessage missingProposal;

    public MissingProposalsMessage() {}

    public MissingProposalsMessage(int id, int sender, ProposalMessage missingProposal) {
        super(id, sender);
        this.missingProposal = missingProposal;
    }

    public ProposalMessage getMissingProposal() {
        return missingProposal;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        missingProposal.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        missingProposal = new ProposalMessage();
        missingProposal.readExternal(in);
    }
}
