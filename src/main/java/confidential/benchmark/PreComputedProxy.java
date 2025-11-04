package confidential.benchmark;

import bftsmart.reconfiguration.IClientSideReconfigurationListener;
import bftsmart.reconfiguration.views.View;
import bftsmart.tom.ExtendedServiceProxy;
import bftsmart.tom.util.ServiceResponse;
import confidential.Configuration;
import confidential.ExtractedResponse;
import confidential.MessageType;
import confidential.Metadata;
import confidential.client.ClientConfidentialityScheme;
import confidential.client.Response;
import confidential.client.ServersResponseHandler;
import confidential.encrypted.EncryptedPublishedShares;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;
import vss.commitment.constant.ConstantCommitment;
import vss.facade.Mode;
import vss.facade.SecretSharingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Robin
 */
public class PreComputedProxy implements IClientSideReconfigurationListener {
    private final Logger logger = LoggerFactory.getLogger("confidential");

    final ExtendedServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;
    private final ServersResponseHandler serversResponseHandler;
    private byte[] commonData;
    Map<Integer, byte[]> privateDataShares;
    private boolean preComputed;
    private final boolean isLinearCommitmentScheme;
    private final boolean isSendAllSharesTogether;
    private byte[] plainData;
    private byte[] privateData;
    private EncryptedPublishedShares[] shares;

    PreComputedProxy(int clientId) throws SecretSharingException {
        if (Configuration.getInstance().useTLSEncryption()) {
            serversResponseHandler = new PreComputedPlainServersResponseHandler();
        } else {
            serversResponseHandler =
                    new PreComputedEncryptedServersResponseHandler(clientId);
        }
        this.service = new ExtendedServiceProxy(clientId, serversResponseHandler,
                serversResponseHandler, serversResponseHandler);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        serversResponseHandler.setClientConfidentialityScheme(confidentialityScheme);
        isLinearCommitmentScheme = confidentialityScheme.isLinearCommitmentScheme();
        isSendAllSharesTogether = Configuration.getInstance().isSendAllSharesTogether();
        service.setInvokeTimeout(60000);
    }

    public void setPreComputedValues(byte[] plainData, byte[] privateData,
									 EncryptedPublishedShares[] shares, byte[] commonData,
									 Map<Integer, byte[]> privateDataShares) {
        if (serversResponseHandler instanceof PreComputedPlainServersResponseHandler) {
			System.out.println("Setting precomputed true in PreComputedPlainServersResponseHandler");
			((PreComputedPlainServersResponseHandler) serversResponseHandler).setPreComputed(true);
		} else if (serversResponseHandler instanceof PreComputedEncryptedServersResponseHandler) {
			System.out.println("Setting precomputed true in PreComputedEncryptedServersResponseHandler");
			((PreComputedEncryptedServersResponseHandler) serversResponseHandler).setPreComputed(true);
		}
        this.preComputed = true;
        this.plainData = plainData;
        this.privateData = privateData;
        this.shares = shares;
        this.commonData = commonData;
        this.privateDataShares = privateDataShares;
    }

    Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
		ServiceResponse response;
		byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
		if (preComputed) {
			response = service.invokeOrdered(commonData,
					confidentialData.length == 0 || isSendAllSharesTogether ? null : privateDataShares, metadata);
		} else {
            EncryptedPublishedShares[] shares = sharePrivateData(confidentialData);
            if (confidentialData.length != 0 && shares == null)
                return null;
            byte[] commonData = serializeCommonData(plainData, shares);
            if (commonData == null)
                return null;

            Map<Integer, byte[]> privateData = null;
            if (!isSendAllSharesTogether && confidentialData.length != 0) {
                int[] servers = service.getViewManager().getCurrentViewProcesses();
                privateData = new HashMap<>(servers.length);
                for (int server : servers) {
                    byte[] b = serializePrivateDataFor(server, shares);
                    privateData.put(server, b);
                }
            }
			response = service.invokeOrdered(commonData, privateData, metadata);
		}
        return preComputed ? null : composeResponse(response);
    }

	Response invokeOrderedHashed(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
		serversResponseHandler.reset();
		ServiceResponse response;
		byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
		if (preComputed) {
			response = service.invokeOrderedHashed(commonData,
					confidentialData.length == 0 || isSendAllSharesTogether ? null : privateDataShares, metadata);
		} else {
			EncryptedPublishedShares[] shares = sharePrivateData(confidentialData);
			if (confidentialData.length != 0 && shares == null)
				return null;
			byte[] commonData = serializeCommonData(plainData, shares);
			if (commonData == null)
				return null;

			Map<Integer, byte[]> privateData = null;
			if (!isSendAllSharesTogether && confidentialData.length != 0) {
				int[] servers = service.getViewManager().getCurrentViewProcesses();
				privateData = new HashMap<>(servers.length);
				for (int server : servers) {
					byte[] b = serializePrivateDataFor(server, shares);
					privateData.put(server, b);
				}
			}
			response = service.invokeOrderedHashed(commonData, privateData, metadata);
		}
		return preComputed ? null : composeResponse(response);
	}

    Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        ServiceResponse response;
		byte metadata = (byte) (confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
		if (preComputed) {
            response = service.invokeUnordered(commonData,
					confidentialData.length == 0 || isSendAllSharesTogether ? null : privateDataShares, metadata);
        } else {
            EncryptedPublishedShares[] shares = sharePrivateData(confidentialData);
            if (confidentialData.length != 0 && shares == null)
                return null;

            byte[] commonData = serializeCommonData(plainData, shares);
            if (commonData == null)
                return null;

            Map<Integer, byte[]> privateData = null;
            if (!isSendAllSharesTogether && confidentialData.length != 0) {
                int[] servers = service.getViewManager().getCurrentViewProcesses();
                privateData = new HashMap<>(servers.length);
                for (int server : servers) {
                    byte[] b = serializePrivateDataFor(server, shares);
                    privateData.put(server, b);
                }
            }
            response = service.invokeUnordered(commonData, privateData, metadata);
        }

        return preComputed ? null : composeResponse(response);
    }

	Response invokeUnorderedHashed(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
		serversResponseHandler.reset();
		ServiceResponse response;
		byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
		if (preComputed) {
			response = service.invokeUnorderedHashed(commonData,
					confidentialData.length == 0 || isSendAllSharesTogether ? null : privateDataShares, metadata);
		} else {
			EncryptedPublishedShares[] shares = sharePrivateData(confidentialData);
			if (confidentialData.length != 0 && shares == null)
				return null;

			byte[] commonData = serializeCommonData(plainData, shares);
			if (commonData == null)
				return null;

			Map<Integer, byte[]> privateData = null;
			if (!isSendAllSharesTogether && confidentialData.length != 0) {
				int[] servers = service.getViewManager().getCurrentViewProcesses();
				privateData = new HashMap<>(servers.length);
				for (int server : servers) {
					byte[] b = serializePrivateDataFor(server, shares);
					privateData.put(server, b);
				}
			}
			response = service.invokeUnorderedHashed(commonData, privateData, metadata);
		}

		return preComputed ? null : composeResponse(response);
	}

    public void close() {
        service.close();
    }

    private Response composeResponse(ServiceResponse response) throws SecretSharingException {
        if (response == null)
            return null;

        ExtractedResponse extractedResponse = (ExtractedResponse) response;

        if (extractedResponse.getThrowable() != null)
            throw extractedResponse.getThrowable();
        return new Response(extractedResponse.getContent(), extractedResponse.getConfidentialData());
    }

    byte[] serializePrivateDataFor(int server, EncryptedPublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            if (shares != null) {
                BigInteger shareholder = confidentialityScheme.getShareholder(server);
                for (EncryptedPublishedShares share : shares) {
                    byte[] encryptedShareBytes = share.getShareOf(server);
                    out.writeInt(encryptedShareBytes == null ? -1 : encryptedShareBytes.length);
                    if (encryptedShareBytes != null)
                        out.write(encryptedShareBytes);
                    if (!isLinearCommitmentScheme) {
                        ConstantCommitment commitment = (ConstantCommitment)share.getCommitment();
                        byte[] witness = commitment.getWitness(shareholder);
                        out.writeInt(witness.length);
                        out.write(witness);
                    }
                }
            }

            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Occurred while composing request", e);
            return null;
        }
    }

    byte[] serializeCommonData(byte[] plainData, EncryptedPublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {

            out.write((byte) MessageType.CLIENT.ordinal());

            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null)
                out.write(plainData);

            out.writeInt(shares == null ? -1 : shares.length);
            if (shares != null) {
                for (EncryptedPublishedShares share : shares) {
                    if (isSendAllSharesTogether) {
                        share.writeExternal(out);
                    } else {
                        byte[] sharedData = share.getSharedData();
                        Commitment commitment = share.getCommitment();
                        out.writeInt(sharedData == null ? -1 : sharedData.length);
                        if (sharedData != null)
                            out.write(sharedData);
                        if (isLinearCommitmentScheme)
                            CommitmentUtils.getInstance().writeCommitment(commitment, out);
                        else {
                            byte[] c = ((ConstantCommitment) commitment).getCommitment();
                            out.writeInt(c.length);
                            out.write(c);
                        }
                    }
                }
            }

            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Occurred while composing request", e);
            return null;
        }
    }

    EncryptedPublishedShares[] sharePrivateData(byte[]... privateData) throws SecretSharingException {
        if (privateData == null)
            return null;
        EncryptedPublishedShares[] result = new EncryptedPublishedShares[privateData.length];
        for (int i = 0; i < privateData.length; i++) {
            result[i] = confidentialityScheme.share(privateData[i], Mode.LARGE_SECRET);
        }
        return result;
    }

    @Override
    public void onReconfiguration(View view) {
        Set<Integer> newServers = new HashSet<>(view.getProcesses().length);
        for (int process : view.getProcesses()) {
            if (confidentialityScheme.getShareholder(process) == null)
                newServers.add(process);
        }
        for (Integer newServer : newServers) {
            try {
                confidentialityScheme.addShareholder(newServer, BigInteger.valueOf(newServer + 1));
            } catch (SecretSharingException e) {
                logger.error("Failed to add new server as shareholder", e);
            }
        }

        updatePreComputedValues();
    }

    private void updatePreComputedValues() {
        try {
			if (privateData.length > 0) {
				shares = sharePrivateData(privateData);
			}
            commonData = serializeCommonData(plainData, shares);
            int[] servers = service.getViewManager().getCurrentViewProcesses();
            privateDataShares = new HashMap<>(servers.length);
			if (privateData.length > 0) {
				for (int server : servers) {
					byte[] b = serializePrivateDataFor(server, shares);
					privateDataShares.put(server, b);
				}
			}
        } catch (SecretSharingException e) {
            logger.error("Failed to update precomputed values", e);
        }
    }
}
