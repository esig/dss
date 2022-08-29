package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.io.Serializable;

/**
 * This service is used for developing a REST/SOAP API for CMS signature generation
 * conformant to PAdES signature format.
 *
 */
public interface RemoteExternalCMSService extends Serializable {

    /**
     * Returns a DTBS (Data To Be Signed) for Signature Value creation.
     *
     * @param messageDigest
     *            {@link DigestDTO} containing message-digest computed on PDF's signature ByteRange
     * @param parameters
     *            {@link RemoteSignatureParameters} set of the signing parameters for CMS signature creation
     * @return {@link DigestDTO} representing the DTBS (Data To Be Signed)
     */
    ToBeSignedDTO getDataToSign(final DigestDTO messageDigest, final RemoteSignatureParameters parameters);

    /**
     * Creates a CMS signature signing the provided {@code messageDigest} compliant for PAdES signature enveloping.
     *
     * @param messageDigest
     *            {@link DigestDTO} containing message-digest computed on PDF's signature ByteRange
     * @param parameters
     *            {@link RemoteSignatureParameters} set of the signing parameters for CMS signature creation
     * @param signatureValue
     *            {@link SignatureValueDTO} the signature value to incorporate
     * @return the CMS signature covering the message-digest for inclusion to a PAdES signature
     */
    RemoteDocument signMessageDigest(final DigestDTO messageDigest, final RemoteSignatureParameters parameters,
                                     SignatureValueDTO signatureValue);

}
