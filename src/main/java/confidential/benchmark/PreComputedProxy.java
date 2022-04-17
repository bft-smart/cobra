package confidential.benchmark;

import bftsmart.tom.ServiceProxy;
import confidential.ConfidentialExtractedResponse;
import confidential.Configuration;
import confidential.MessageType;
import confidential.Metadata;
import confidential.client.ClientConfidentialityScheme;
import confidential.client.Response;
import confidential.client.ServersResponseHandler;
import confidential.encrypted.EncryptedPublishedShares;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.constant.ConstantCommitment;
import vss.facade.Mode;
import vss.facade.SecretSharingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Robin
 */
public class PreComputedProxy {
    private final Logger logger = LoggerFactory.getLogger("confidential");

    final ServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;
    private final ServersResponseHandler serversResponseHandler;
    private byte[] orderedCommonData;
    private byte[] unorderedCommonData;
    Map<Integer, byte[]> privateData;
    private boolean preComputed;
    private final boolean isLinearCommitmentScheme;
    private final boolean isSendAllSharesTogether;
    private byte[] data;
    private byte[] plainWriteData;
    private byte[] plainReadData;
    private EncryptedPublishedShares[] shares;

    PreComputedProxy(int clientId) throws SecretSharingException {
        this.preComputed = false;
        if (Configuration.getInstance().useTLSEncryption()) {
            serversResponseHandler = new PreComputedPlainServersResponseHandler();
        } else {
            serversResponseHandler =
                    new PreComputedEncryptedServersResponseHandler(clientId);
        }
        this.service = new ServiceProxy(clientId, null, serversResponseHandler,
                serversResponseHandler, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        serversResponseHandler.setClientConfidentialityScheme(confidentialityScheme);
        isLinearCommitmentScheme = confidentialityScheme.isLinearCommitmentScheme();
        isSendAllSharesTogether = Configuration.getInstance().isSendAllSharesTogether();
        service.setInvokeTimeout(60000);
    }

    public void setPreComputedValues(byte[] data, byte[] plainWriteData, byte[] plainReadData,
                                     EncryptedPublishedShares[] shares, byte[] orderedCommonData,
                                     Map<Integer, byte[]> privateData,
                                     byte[] unorderedCommonData) {
        if (serversResponseHandler instanceof PreComputedPlainServersResponseHandler)
            ((PreComputedPlainServersResponseHandler)serversResponseHandler).setPreComputed(true);
        else if (serversResponseHandler instanceof PreComputedEncryptedServersResponseHandler)
            ((PreComputedEncryptedServersResponseHandler)serversResponseHandler).setPreComputed(true);
        this.preComputed = true;
        this.data = data;
        this.plainWriteData = plainWriteData;
        this.plainReadData = plainReadData;
        this.shares = shares;
        this.orderedCommonData = orderedCommonData;
        this.privateData = privateData;
        this.unorderedCommonData = unorderedCommonData;
    }

    Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        ConfidentialExtractedResponse response = invokeOrdered2(plainData, confidentialData);
        return preComputed ? null : composeResponse(response);
    }
    ConfidentialExtractedResponse invokeOrdered2(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        ConfidentialExtractedResponse response;
        if (preComputed) {
            byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = (ConfidentialExtractedResponse) service.invokeOrdered2(confidentialData.length == 0 ? unorderedCommonData : orderedCommonData,
                    confidentialData.length == 0 || isSendAllSharesTogether ? null : privateData, metadata);
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
            byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = (ConfidentialExtractedResponse) service.invokeOrdered2(commonData, privateData, metadata);
        }
        return response;
    }

    Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        ConfidentialExtractedResponse response = invokeUnordered2(plainData, confidentialData);
        return preComputed ? null : composeResponse(response);
    }

    ConfidentialExtractedResponse invokeUnordered2(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        ConfidentialExtractedResponse response;
        if (preComputed) {
            byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = (ConfidentialExtractedResponse) service.invokeUnordered2(unorderedCommonData, null, metadata);
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
            byte metadata = (byte)(confidentialData.length == 0 ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = (ConfidentialExtractedResponse) service.invokeUnordered2(commonData, privateData, metadata);
        }

        return response;
    }

    public void close() {
        service.close();
    }

    private Response composeResponse(ConfidentialExtractedResponse response) throws SecretSharingException {
        if (response == null)
            return null;
        if (response.getThrowable() != null)
            throw response.getThrowable();
        return new Response(response.getPlainData(), response.getConfidentialData());
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
                            confidentialityScheme.getCommitmentScheme().writeCommitment(commitment, out);
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
}
