package confidential.statemanagement;

import bftsmart.statemanagement.SMMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * @author robin
 */
public class PolynomialRecovery extends SMMessage {
	private int id;
	private int stateSenderReplica;
	private int serverPort;
	private int[] polynomialInitialIds;
	private int[] nPolynomialsPerId;

	public PolynomialRecovery() {}

	public PolynomialRecovery(int id, int sender, int type, int stateSenderReplica, int serverPort, int[] polynomialInitialIds,
							  int[] nPolynomialsPerId) {
		super(sender, -1, type, null, null, -1, -1);
		this.id = id;
		this.stateSenderReplica = stateSenderReplica;
		this.serverPort = serverPort;
		this.polynomialInitialIds = polynomialInitialIds;
		this.nPolynomialsPerId = nPolynomialsPerId;
	}

	public int getId() {
		return id;
	}

	public int getServerPort() {
		return serverPort;
	}

	public int getStateSenderReplica() {
		return stateSenderReplica;
	}

	public int[] getPolynomialInitialIds() {
		return polynomialInitialIds;
	}

	public int[] getNPolynomialsPerId() {
		return nPolynomialsPerId;
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		super.readExternal(in);
		id = in.readInt();
		stateSenderReplica = in.readInt();
		serverPort = in.readInt();
		int size = in.readInt();
		polynomialInitialIds = new int[size];
		nPolynomialsPerId = new int[size];

		for (int i = 0; i < size; i++) {
			polynomialInitialIds[i] = in.readInt();
		}

		for (int i = 0; i < size; i++) {
			nPolynomialsPerId[i] = in.readInt();
		}
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(id);
		out.writeInt(stateSenderReplica);
		out.writeInt(serverPort);
		out.writeInt(polynomialInitialIds.length);
		for (int polynomialInitialId : polynomialInitialIds) {
			out.writeInt(polynomialInitialId);
		}
		for (int i : nPolynomialsPerId) {
			out.writeInt(i);
		}
	}
}
