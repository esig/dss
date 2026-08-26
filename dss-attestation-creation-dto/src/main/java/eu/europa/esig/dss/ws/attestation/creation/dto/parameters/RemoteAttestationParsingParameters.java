package eu.europa.esig.dss.ws.attestation.creation.dto.parameters;

import eu.europa.esig.dss.enumerations.AttestationForm;

/**
 * Parameters used for an attestation parsing method
 *
 */
public class RemoteAttestationParsingParameters {

    /** Attestation form */
    private AttestationForm attestationForm;

    /**
     * Constructor to create an empty object
     */
    public RemoteAttestationParsingParameters() {
        // empty
    }

    /**
     * Constructor with attestation form defined
     *
     * @param attestationForm {@link AttestationForm}
     */
    public RemoteAttestationParsingParameters(AttestationForm attestationForm) {
        this.attestationForm = attestationForm;
    }

    /**
     * Gets the attestation form
     *
     * @return {@link AttestationForm}
     */
    public AttestationForm getAttestationForm() {
        return attestationForm;
    }

    /**
     * Sets the attestation form
     *
     * @param attestationForm {@link AttestationForm}
     */
    public void setAttestationForm(AttestationForm attestationForm) {
        this.attestationForm = attestationForm;
    }

}
