package confidential.reconfiguration;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * @author robin
 */
public class ReconfigurationParameters implements Externalizable {
	private int oldF;
	private int[] oldGroup;
	private int newF;
	private int[] newGroup;
	private Set<Integer> offlineServers;
	private int recentCID;

	public ReconfigurationParameters() {}

	public ReconfigurationParameters(int oldF, int[] oldGroup, int newF, int[] newGroup) {
		this.oldF = oldF;
		this.oldGroup = oldGroup;
		this.newF = newF;
		this.newGroup = newGroup;
		this.offlineServers = new HashSet<>(newGroup.length);
		for (int server : newGroup) {
			offlineServers.add(server);
		}
		for (int server : oldGroup) {
			offlineServers.remove(server);
		}
	}

	public void serverIsOnline(int server) {
		offlineServers.remove(server);
	}

	public boolean isNewGroupActive() {
		return offlineServers.isEmpty();
	}

	//This method can be optimized using a Set
	public boolean isInNewGroup(int server) {
		for (int i : newGroup) {
			if (i == server)
				return true;
		}
		return false;
	}

	//This method can be optimized using a Set
	public boolean isInOldGroup(int server) {
		for (int i : oldGroup) {
			if (i == server)
				return true;
		}
		return false;
	}

	public int getOldF() {
		return oldF;
	}

	public int[] getOldGroup() {
		return oldGroup;
	}

	public int getNewF() {
		return newF;
	}

	public int[] getNewGroup() {
		return newGroup;
	}

	public void updateCID(int cid) {
		recentCID = Math.max(recentCID, cid);
	}

	public int getRecentCID() {
		return recentCID;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(oldF);
		out.writeInt(oldGroup.length);
		for (int i : oldGroup) {
			out.writeInt(i);
		}
		out.writeInt(newF);
		out.writeInt(newGroup.length);
		for (int i : newGroup) {
			out.writeInt(i);
		}
		out.writeInt(offlineServers.size());
		for (Integer offlineServer : offlineServers) {
			out.writeInt(offlineServer);
		}
		out.writeInt(recentCID);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		oldF = in.readInt();
		oldGroup = new int[in.readInt()];
		for (int i = 0; i < oldGroup.length; i++) {
			oldGroup[i] = in.readInt();
		}
		newF = in.readInt();
		newGroup = new int[in.readInt()];
		for (int i = 0; i < newGroup.length; i++) {
			newGroup[i] = in.readInt();
		}
		int size = in.readInt();
		offlineServers = new HashSet<>(size);
		while (size-- > 0) {
			offlineServers.add(in.readInt());
		}
		recentCID = in.readInt();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ReconfigurationParameters that = (ReconfigurationParameters) o;
		return oldF == that.oldF && newF == that.newF && recentCID == that.recentCID && Arrays.equals(oldGroup, that.oldGroup) && Arrays.equals(newGroup, that.newGroup) && Objects.equals(offlineServers, that.offlineServers);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(oldF, newF, offlineServers, recentCID);
		result = 31 * result + Arrays.hashCode(oldGroup);
		result = 31 * result + Arrays.hashCode(newGroup);
		return result;
	}

	@Override
	public String toString() {
		return "ReconfigurationParameters{" +
				"oldF=" + oldF +
				", oldGroup=" + Arrays.toString(oldGroup) +
				", newF=" + newF +
				", newGroup=" + Arrays.toString(newGroup) +
				", offlineServers=" + offlineServers +
				", recentCID=" + recentCID +
				'}';
	}
}
