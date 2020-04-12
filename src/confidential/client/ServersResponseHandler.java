package confidential.client;

import bftsmart.tom.util.Extractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;

import java.util.Comparator;

/**
 * @author Robin
 */
public abstract class ServersResponseHandler implements Comparator<byte[]>, Extractor {
    protected final Logger logger = LoggerFactory.getLogger("confidential");
    protected CommitmentScheme commitmentScheme;
    protected ClientConfidentialityScheme confidentialityScheme;

    public void setClientConfidentialityScheme(ClientConfidentialityScheme confidentialityScheme) {
        this.confidentialityScheme = confidentialityScheme;
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
    }

    public abstract void reset();
}
