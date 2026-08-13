package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteListOfTrustedEntitiesSignatureParameters;

/**
 * DTO for getDataToSign(..) method call for a List of Trusted Entities creation.
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation).
 *
 */
public class DataToSignListOfTrustedEntitiesDTO {

    /** Document to be signed */
    private RemoteDocument listOfTrustedEntities;

    /** The signature parameters */
    private RemoteListOfTrustedEntitiesSignatureParameters parameters;

    /**
     * Empty constructor
     */
    public DataToSignListOfTrustedEntitiesDTO() {
        // empty
    }

    /**
     * Default constructor with customizable parameters
     *
     * @param listOfTrustedEntities
     *                  {@link RemoteDocument} List of Trusted Entities to be signed
     * @param parameters
     *                  {@link RemoteListOfTrustedEntitiesSignatureParameters} customizable signature parameters
     */
    public DataToSignListOfTrustedEntitiesDTO(RemoteDocument listOfTrustedEntities, RemoteListOfTrustedEntitiesSignatureParameters parameters) {
        this.listOfTrustedEntities = listOfTrustedEntities;
        this.parameters = parameters;
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
     * Gets signature parameters for List of Trusted Entities signing
     *
     * @return {@link RemoteListOfTrustedEntitiesSignatureParameters}
     */
    public RemoteListOfTrustedEntitiesSignatureParameters getParameters() {
        return parameters;
    }

    /**
     * Sets signature parameters for List of Trusted Entities signing
     *
     * @param parameters {@link RemoteListOfTrustedEntitiesSignatureParameters}
     */
    public void setParameters(RemoteListOfTrustedEntitiesSignatureParameters parameters) {
        this.parameters = parameters;
    }

}
