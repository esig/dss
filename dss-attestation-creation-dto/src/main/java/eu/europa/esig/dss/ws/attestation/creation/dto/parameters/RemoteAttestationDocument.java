package eu.europa.esig.dss.ws.attestation.creation.dto.parameters;

import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

public class RemoteAttestationDocument {

    private RemoteDocument signedAttestation;

    private List<DisclosureDTO> disclosures;

    public RemoteAttestationDocument() {
        // empty
    }

    public RemoteAttestationDocument(final RemoteDocument signedAttestation, final List<DisclosureDTO> disclosures) {
        this.signedAttestation = signedAttestation;
        this.disclosures = disclosures;
    }

    public RemoteDocument getSignedAttestation() {
        return signedAttestation;
    }

    public void setSignedAttestation(RemoteDocument signedAttestation) {
        this.signedAttestation = signedAttestation;
    }

    public List<DisclosureDTO> getDisclosures() {
        return disclosures;
    }

    public void setDisclosures(List<DisclosureDTO> disclosures) {
        this.disclosures = disclosures;
    }
}
