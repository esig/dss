package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTrustedListSignatureParameters;

import java.io.Serializable;

/**
 * Service to be used for a simplified straight-forward signing of a Trusted List
 *
 */
public interface RemoteTrustedListSignatureService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed for a conformant XML Trusted List signing
     * according to a set of customizable parameters
     *
     * @param trustedList
     *            {@link RemoteDocument} XML trusted list to be signed (the full XML file shall be provided)
     * @param parameters
     *            {@link RemoteTrustedListSignatureParameters} set of the signing parameters
     *                                                         for Trusted List signature creation
     * @return the data to be signed
     * @throws DSSException
     *             if an error occurred
     */
    ToBeSignedDTO getDataToSign(final RemoteDocument trustedList, final RemoteTrustedListSignatureParameters parameters)
            throws DSSException;

    /**
     * Signs the XML Trusted List with the provided {@code signatureValue} according to a set of customizable parameters.
     * This method produces a signed XML Trusted List with an enveloped signature.
     *
     * @param trustedList
     *            {@link RemoteDocument} XML trusted list to be signed (the full XML file shall be provided)
     * @param parameters
     *            {@link RemoteTrustedListSignatureParameters} set of the signing parameters
     * @param signatureValue
     *            {@link SignatureValueDTO} the signature value to incorporate
     * @return the signed XML Trusted List with an enveloped signature
     * @throws DSSException
     *             if an error occurred
     */
    RemoteDocument signDocument(final RemoteDocument trustedList, final RemoteTrustedListSignatureParameters parameters,
                                final SignatureValueDTO signatureValue) throws DSSException;

}
