package confidential.benchmark;

import bftsmart.tom.ServiceProxy;
import confidential.Configuration;
import confidential.ExtractedResponse;
import confidential.MessageType;
import confidential.Metadata;
import confidential.client.ClientConfidentialityScheme;
import confidential.client.Response;
import confidential.client.ServersResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.Utils;
import vss.commitment.Commitment;
import vss.commitment.constant.ConstantCommitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.EncryptedShare;
import vss.secretsharing.PrivatePublishedShares;

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
    private final boolean preComputed;
    private final boolean isLinearCommitmentScheme;

    PreComputedProxy(int clientId) throws SecretSharingException {
        this.preComputed = false;
        if (Configuration.getInstance().useTLSEncryption()) {
            serversResponseHandler = new PreComputedPlainServersResponseHandler(false);
        } else {
            serversResponseHandler =
                    new PreComputedEncryptedServersResponseHandler(clientId, false);
        }
        this.service = new ServiceProxy(clientId, null, serversResponseHandler,
                serversResponseHandler, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        serversResponseHandler.setClientConfidentialityScheme(confidentialityScheme);
        isLinearCommitmentScheme = confidentialityScheme.isLinearCommitmentScheme();
    }

    PreComputedProxy(int clientId, byte[] unorderedCommonData, byte[] orderedCommonData,
                     Map<Integer, byte[]> privateData) throws SecretSharingException {
        this.preComputed = true;
        if (Configuration.getInstance().useTLSEncryption()) {
            serversResponseHandler = new PreComputedPlainServersResponseHandler(true);
        } else {
            serversResponseHandler =
                    new PreComputedEncryptedServersResponseHandler(clientId, true);
        }
        this.service = new ServiceProxy(clientId, null, serversResponseHandler,
                serversResponseHandler, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        serversResponseHandler.setClientConfidentialityScheme(confidentialityScheme);
        isLinearCommitmentScheme = confidentialityScheme.isLinearCommitmentScheme();
        this.unorderedCommonData = unorderedCommonData;
        this.orderedCommonData = orderedCommonData;
        this.privateData = privateData;
    }

    Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        byte[] response;
        if (preComputed) {
            byte metadata = (byte)(privateData == null ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = service.invokeOrdered(orderedCommonData, privateData, metadata);
        } else {
            PrivatePublishedShares[] shares = sharePrivateData(confidentialData);
            if (confidentialData != null && shares == null)
                return null;
            byte[] commonData = serializeCommonData(plainData, shares);
            if (commonData == null)
                return null;

            Map<Integer, byte[]> privateData = null;
            if (confidentialData != null){
                int[] servers = service.getViewManager().getCurrentViewProcesses();
                privateData = new HashMap<>(servers.length);
                for (int server : servers) {
                    byte[] b = serializePrivateDataFor(server, shares);
                    privateData.put(server, b);
                }
            }
            byte metadata = (byte)(privateData == null ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = service.invokeOrdered(commonData, privateData, metadata);
        }
        return preComputed ? null : composeResponse(response);
    }

    Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        byte[] response;
        if (preComputed) {
            byte metadata = (byte)(privateData == null ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = service.invokeUnordered(unorderedCommonData, null, metadata);
        } else {
            PrivatePublishedShares[] shares = sharePrivateData(confidentialData);
            if (confidentialData != null && shares == null)
                return null;
            byte[] commonData = serializeCommonData(plainData, shares);
            if (commonData == null)
                return null;

            Map<Integer, byte[]> privateData = null;
            if (confidentialData != null){
                int[] servers = service.getViewManager().getCurrentViewProcesses();
                privateData = new HashMap<>(servers.length);
                for (int server : servers) {
                    byte[] b = serializePrivateDataFor(server, shares);
                    privateData.put(server, b);
                }
            }
            byte metadata = (byte)(privateData == null ? Metadata.DOES_NOT_VERIFY.ordinal() : Metadata.VERIFY.ordinal());
            response = service.invokeUnordered(commonData, privateData, metadata);
        }

        return preComputed ? null : composeResponse(response);
    }

    public void close() {
        service.close();
    }

    private Response composeResponse(byte[] response) throws SecretSharingException {
        if (response == null)
            return null;
        ExtractedResponse extractedResponse = ExtractedResponse.deserialize(response);
        if (extractedResponse == null)
            return null;
        if (extractedResponse.getThrowable() != null)
            throw extractedResponse.getThrowable();
        return new Response(extractedResponse.getPlainData(), extractedResponse.getConfidentialData());
    }

    byte[] serializePrivateDataFor(int server, PrivatePublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            if (shares != null) {
                BigInteger shareholder = confidentialityScheme.getShareholder(server);
                for (PrivatePublishedShares share : shares) {
                    EncryptedShare encryptedShare = share.getShareOf(shareholder);
                    byte[] encryptedShareBytes = encryptedShare.getEncryptedShare();
                    out.writeInt(encryptedShareBytes == null ? -1 : encryptedShareBytes.length);
                    if (encryptedShareBytes != null)
                        out.write(encryptedShareBytes);
                    if (!isLinearCommitmentScheme) {
                        ConstantCommitment commitment = (ConstantCommitment)share.getCommitments();
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

    byte[] serializeCommonData(byte[] plainData, PrivatePublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {

            out.write((byte) MessageType.CLIENT.ordinal());

            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null)
                out.write(plainData);

            out.writeInt(shares == null ? -1 : shares.length);
            if (shares != null) {
                for (PrivatePublishedShares share : shares) {
                    byte[] sharedData = share.getSharedData();
                    Commitment commitment = share.getCommitments();
                    out.writeInt(sharedData == null ? -1 : sharedData.length);
                    if (sharedData != null)
                        out.write(sharedData);
                    if (isLinearCommitmentScheme)
                        Utils.writeCommitment(commitment, out);
                    else {
                        byte[] c = ((ConstantCommitment)commitment).getCommitment();
                        out.writeInt(c.length);
                        out.write(c);
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

    PrivatePublishedShares[] sharePrivateData(byte[]... privateData) throws SecretSharingException {
        if (privateData == null)
            return null;
        PrivatePublishedShares[] result = new PrivatePublishedShares[privateData.length];
        for (int i = 0; i < privateData.length; i++) {
            result[i] = confidentialityScheme.share(privateData[i]);
        }
        return result;
    }
}
