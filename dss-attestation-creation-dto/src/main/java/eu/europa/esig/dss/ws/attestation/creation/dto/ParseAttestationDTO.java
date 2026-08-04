package eu.europa.esig.dss.ws.attestation.creation.dto;

import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationParsingParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

/**
 * Data-transfer-object for a #parseAttestation method configuration
 *
 */
public class ParseAttestationDTO {

    /** Attestation document */
    private RemoteDocument attestation;

    /** Parameters for attestation parsing */
    private RemoteAttestationParsingParameters attestationParsingParameters;

    /**
     * Empty constructor
     */
    public ParseAttestationDTO() {
        // empty
    }

    /**
     * Constructor with attestation and parsing parameters provided
     *
     * @param attestation {@link RemoteDocument} to be parsed
     * @param attestationParsingParameters {@link RemoteAttestationParsingParameters}
     */
    public ParseAttestationDTO(RemoteDocument attestation, RemoteAttestationParsingParameters attestationParsingParameters) {
        this.attestation = attestation;
        this.attestationParsingParameters = attestationParsingParameters;
    }

    /**
     * Gets the signed attestation document
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getAttestation() {
        return attestation;
    }

    /**
     * Sets a signed attestation document
     *
     * @param attestation {@link RemoteDocument}
     */
    public void setAttestation(RemoteDocument attestation) {
        this.attestation = attestation;
    }

    /**
     * Gets the attestation parsing parameters
     *
     * @return {@link RemoteAttestationParsingParameters}
     */
    public RemoteAttestationParsingParameters getAttestationParsingParameters() {
        return attestationParsingParameters;
    }

    /**
     * Sets the attestation parsing parameters
     *
     * @param attestationParsingParameters {@link RemoteAttestationParsingParameters}
     */
    public void setAttestationParsingParameters(RemoteAttestationParsingParameters attestationParsingParameters) {
        this.attestationParsingParameters = attestationParsingParameters;
    }

}
