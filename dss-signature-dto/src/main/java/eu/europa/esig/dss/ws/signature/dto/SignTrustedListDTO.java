package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTrustedListSignatureParameters;

import java.io.Serializable;

/**
 * DTO to be used for the method signDocument(..) for Trusted List signing.
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation).
 *
 */
public class SignTrustedListDTO implements Serializable {

    private static final long serialVersionUID = 7274971797590600434L;

    /** Document to be signed */
    private RemoteDocument trustedList;

    /** The signature parameters */
    private RemoteTrustedListSignatureParameters parameters;

    /** The SignatureValue */
    private SignatureValueDTO signatureValue;

    /**
     * Empty constructor
     */
    public SignTrustedListDTO() {
    }

    /**
     * Default constructor with parameters
     *
     * @param trustedList
     *                  {@link RemoteDocument} XML Trusted List to be signed
     *                                         (shall be represented by a full document binaries)
     * @param parameters
     *                  {@link RemoteTrustedListSignatureParameters} a set of customizable parameters
     * @param signatureValue
     *                  {@link SignatureValueDTO} created signature value
     */
    public SignTrustedListDTO(RemoteDocument trustedList, RemoteTrustedListSignatureParameters parameters,
                              SignatureValueDTO signatureValue) {
        this.trustedList = trustedList;
        this.parameters = parameters;
        this.signatureValue = signatureValue;
    }

    /**
     * Gets an XML Trusted List to be signed
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getTrustedList() {
        return trustedList;
    }

    /**
     * Sets an XML Trusted List to be signed
     *
     * @param trustedList {@link RemoteDocument}
     */
    public void setTrustedList(RemoteDocument trustedList) {
        this.trustedList = trustedList;
    }

    /**
     * Gets a set of customizable parameters
     *
     * @return {@link RemoteTrustedListSignatureParameters}
     */
    public RemoteTrustedListSignatureParameters getParameters() {
        return parameters;
    }

    /**
     * Sets a set of customizable parameters (optional)
     *
     * @param parameters {@link RemoteTrustedListSignatureParameters}
     */
    public void setParameters(RemoteTrustedListSignatureParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * Gets a signature value
     *
     * @return {@link SignatureValueDTO}
     */
    public SignatureValueDTO getSignatureValue() {
        return signatureValue;
    }

    /**
     * Sets a signature value
     *
     * @param signatureValue {@link SignatureValueDTO}
     */
    public void setSignatureValue(SignatureValueDTO signatureValue) {
        this.signatureValue = signatureValue;
    }

}
