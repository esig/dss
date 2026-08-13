package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteListOfTrustedEntitiesSignatureParameters;

import java.io.Serializable;

/**
 * DTO to be used for the method signDocument(..) for List of Trusted Entities signing.
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation).
 *
 */
public class SignListOfTrustedEntitiesDTO implements Serializable {

    private static final long serialVersionUID = 7274971797590600434L;

    /** Document to be signed */
    private RemoteDocument listOfTrustedEntities;

    /** The signature parameters */
    private RemoteListOfTrustedEntitiesSignatureParameters parameters;

    /** The SignatureValue */
    private SignatureValueDTO signatureValue;

    /**
     * Empty constructor
     */
    public SignListOfTrustedEntitiesDTO() {
        // empty
    }

    /**
     * Default constructor with parameters
     *
     * @param listOfTrustedEntities
     *                  {@link RemoteDocument} List of Trusted Entities to be signed
     *                                         (shall be represented by a full document binaries)
     * @param parameters
     *                  {@link RemoteListOfTrustedEntitiesSignatureParameters} a set of customizable parameters
     * @param signatureValue
     *                  {@link SignatureValueDTO} created signature value
     */
    public SignListOfTrustedEntitiesDTO(RemoteDocument listOfTrustedEntities, RemoteListOfTrustedEntitiesSignatureParameters parameters,
                                        SignatureValueDTO signatureValue) {
        this.listOfTrustedEntities = listOfTrustedEntities;
        this.parameters = parameters;
        this.signatureValue = signatureValue;
    }

    /**
     * Gets a List of Trusted Entities to be signed
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getListOfTrustedEntities() {
        return listOfTrustedEntities;
    }

    /**
     * Sets a List of Trusted Entities to be signed
     *
     * @param listOfTrustedEntities {@link RemoteDocument}
     */
    public void setListOfTrustedEntities(RemoteDocument listOfTrustedEntities) {
        this.listOfTrustedEntities = listOfTrustedEntities;
    }

    /**
     * Gets a set of customizable parameters
     *
     * @return {@link RemoteListOfTrustedEntitiesSignatureParameters}
     */
    public RemoteListOfTrustedEntitiesSignatureParameters getParameters() {
        return parameters;
    }

    /**
     * Sets a set of customizable parameters (optional)
     *
     * @param parameters {@link RemoteListOfTrustedEntitiesSignatureParameters}
     */
    public void setParameters(RemoteListOfTrustedEntitiesSignatureParameters parameters) {
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
