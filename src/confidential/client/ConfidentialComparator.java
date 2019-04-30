package confidential.client;

import confidential.ConfidentialMessage;

import java.util.Comparator;

public class ConfidentialComparator implements Comparator<byte[]> {
    @Override
    public int compare(byte[] o1, byte[] o2) {
        ConfidentialMessage response1 = ConfidentialMessage.deserialize(o1);
        ConfidentialMessage response2= ConfidentialMessage.deserialize(o2);
        if (response1 == null && response2 == null)
            return 0;
        if (response1 == null)
            return 1;
        if (response2 == null)
            return -1;
        return response1.hashCode() - response2.hashCode();
    }
}
