package confidential.statemanagement;

import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import vss.commitment.Commitments;

public class RecoveryApplicationState extends DefaultApplicationState {
    private Commitments transferPolynomialCommitments;

    public RecoveryApplicationState() {}

    public RecoveryApplicationState(CommandsInfo[] messageBatches, int lastCheckpointCID, int lastCID,
                                    byte[] state, byte[] stateHash, int pid, Commitments transferPolynomialCommitments) {
        super(messageBatches, lastCheckpointCID, lastCID, state, stateHash, pid);
        this.transferPolynomialCommitments = transferPolynomialCommitments;
    }

    public Commitments getTransferPolynomialCommitments() {
        return transferPolynomialCommitments;
    }
}
