package eu.europa.esig.dss.ws.attestation.creation.dto.parameters;

import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

/**
 * Represents an attestation document, with a separated attestation signature and selective disclosures parts
 *
 */
public class RemoteAttestationDocument {

    /** Signed attestation document */
    private RemoteDocument signedAttestation;

    /** List of attached selectively disclosable claims */
    private List<DisclosureDTO> disclosures;

    /**
     * Default constructor to instantiate an empty object
     */
    public RemoteAttestationDocument() {
        // empty
    }

    /**
     * Constructor with provided signed attestation and selectively disclosable claims
     *
     * @param signedAttestation {@link RemoteDocument} containing the attestation signature
     * @param disclosures a list of {@link DisclosureDTO}s
     */
    public RemoteAttestationDocument(final RemoteDocument signedAttestation, final List<DisclosureDTO> disclosures) {
        this.signedAttestation = signedAttestation;
        this.disclosures = disclosures;
    }

    /**
     * Gets the signed attestation
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getSignedAttestation() {
        return signedAttestation;
    }

    /**
     * Sets the signed attestation
     *
     * @param signedAttestation {@link RemoteDocument}
     */
    public void setSignedAttestation(RemoteDocument signedAttestation) {
        this.signedAttestation = signedAttestation;
    }

    /**
     * Gets a list of selectively disclosable claims
     *
     * @return a list of {@link DisclosureDTO}s
     */
    public List<DisclosureDTO> getDisclosures() {
        return disclosures;
    }

    /**
     * Sets a list of selectively disclosable claims
     *
     * @param disclosures a list of {@link DisclosureDTO}s
     */
    public void setDisclosures(List<DisclosureDTO> disclosures) {
        this.disclosures = disclosures;
    }

}
