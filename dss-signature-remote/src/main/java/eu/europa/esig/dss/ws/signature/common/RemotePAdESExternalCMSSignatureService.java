package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.io.Serializable;

/**
 * This service is used for developing a REST/SOAP API for PAdES signing using an external CMS signature provider
 *
 */
public interface RemotePAdESExternalCMSSignatureService extends Serializable {

    /**
     * Creates a signature revision for the given PDF {@code toSignDocument} according
     * to the provided {@code parameters} and returns the message-digest computed on the extracted ByteRange content.
     * <p>
     * NOTE : {@code parameters} do not need to contain signing-certificate and certificate chain,
     *        as they are a part of CMS signature.
     *
     * @param toSignDocument
     *            {@link RemoteDocument} representing PDF document to be signed
     * @param parameters
     *            {@link RemoteSignatureParameters} set of the signing parameters for PAdES signature creation
     * @return {@link DigestDTO} representing the message-digest to be used for CMS signature creation
     */
    DigestDTO getDigestToSign(final RemoteDocument toSignDocument, final RemoteSignatureParameters parameters);

    /**
     * Signs the {@code toSignDocument} by incorporating the provided {@code cmsSignature}
     * within computed PDF signature revision.
     *
     * @param toSignDocument
     *            {@link RemoteDocument} representing PDF document to be signed
     * @param parameters
     *            {@link RemoteSignatureParameters} set of the signing parameters for PAdES signature creation
     * @param cmsSignature
     *            {@link RemoteDocument} representing a CMS signature (CMSSignedData) returned by an external provider
     * @return {@link RemoteDocument} representing the signed PDF document
     */
    RemoteDocument signDocument(final RemoteDocument toSignDocument, final RemoteSignatureParameters parameters,
                                final RemoteDocument cmsSignature);


}
