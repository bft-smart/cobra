package vss.commitment;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public final class CommitmentUtils {
	private static CommitmentUtils instance;
	private final CommitmentScheme commitmentScheme;

	public static void initialize(CommitmentScheme commitmentScheme) {
		if (instance == null)
			instance = new CommitmentUtils(commitmentScheme);
	}

	public CommitmentUtils(CommitmentScheme commitmentScheme) {
		this.commitmentScheme = commitmentScheme;
	}

	public static CommitmentUtils getInstance() {
		return instance;
	}

	public void writeCommitment(Commitment commitment, ObjectOutput out) throws IOException {
		commitmentScheme.writeCommitment(commitment, out);
	}

	public Commitment readCommitment(ObjectInput in) throws IOException, ClassNotFoundException {
		return commitmentScheme.readCommitment(in);
	}
}
