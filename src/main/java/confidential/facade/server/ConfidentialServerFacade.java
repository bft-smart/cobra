package confidential.facade.server;

import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.Replier;
import bftsmart.tom.server.RequestVerifier;
import bftsmart.tom.util.KeyLoader;
import confidential.server.ConfidentialRecoverable;

import java.security.Provider;

/**
 * @author Robin
 */
public final class ConfidentialServerFacade {

    public ConfidentialServerFacade(int processId,
                                    ConfidentialSingleExecutable confidentialExecutor) {
        this(processId, confidentialExecutor, null, null, null, null);
    }

    public ConfidentialServerFacade(int processId,
                                    ConfidentialSingleExecutable confidentialExecutor,
                                    RequestVerifier requestVerifier) {
        this(processId, confidentialExecutor, requestVerifier, null, null, null);
    }

    public ConfidentialServerFacade(int processId,
                                    ConfidentialSingleExecutable confidentialExecutor,
                                    Replier replier) {
        this(processId, confidentialExecutor, null, replier, null, null);
    }

    public ConfidentialServerFacade(int processId,
                                    ConfidentialSingleExecutable confidentialExecutor,
                                    KeyLoader loader,
                                    Provider provider) {
        this(processId, confidentialExecutor, null, null, loader, provider);
    }

    public ConfidentialServerFacade(int processId,
                                    ConfidentialSingleExecutable confidentialExecutor,
                                    RequestVerifier requestVerifier,
                                    Replier replier,
                                    KeyLoader loader,
                                    Provider provider) {
        ConfidentialRecoverable cr =
                new ConfidentialRecoverable(processId, confidentialExecutor);
        new ServiceReplica(processId, cr, cr, requestVerifier, replier, loader,
                provider, cr);
    }
}
