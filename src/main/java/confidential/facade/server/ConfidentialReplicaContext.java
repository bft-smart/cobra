package confidential.facade.server;

import bftsmart.tom.ReplicaContext;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.polynomial.DistributedPolynomial;
import confidential.server.ServerConfidentialityScheme;

public class ConfidentialReplicaContext {
	private final ReplicaContext replicaContext;
	private final InterServersCommunication interServersCommunication;
	private final ServerConfidentialityScheme confidentialityScheme;
	private final DistributedPolynomial distributedPolynomial;

	public ConfidentialReplicaContext(ReplicaContext replicaContext, InterServersCommunication interServersCommunication,
									  ServerConfidentialityScheme confidentialityScheme, DistributedPolynomial distributedPolynomial) {
		this.replicaContext = replicaContext;
		this.interServersCommunication = interServersCommunication;
		this.confidentialityScheme = confidentialityScheme;
		this.distributedPolynomial = distributedPolynomial;
	}

	public ReplicaContext getReplicaContext() {
		return replicaContext;
	}

	public InterServersCommunication getInterServersCommunication() {
		return interServersCommunication;
	}

	public ServerConfidentialityScheme getConfidentialityScheme() {
		return confidentialityScheme;
	}

	public DistributedPolynomial getDistributedPolynomial() {
		return distributedPolynomial;
	}
}
