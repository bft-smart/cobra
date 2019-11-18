package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.List;

public class ProcessedVotesMessage extends PolynomialMessage {
    private List<VoteMessage> votes;

    public ProcessedVotesMessage() {}

    public ProcessedVotesMessage(int id, int processId, List<VoteMessage> votes) {
        super(id, processId);
        this.votes = votes;
    }

    public List<VoteMessage> getVotes() {
        return votes;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(votes.size());
        for (VoteMessage vote : votes)
            vote.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        int size = in.readInt();
        votes = new ArrayList<>(size);
        while (size-- > 0) {
            VoteMessage vote = new VoteMessage();
            vote.readExternal(in);
            votes.add(vote);
        }
    }
}
