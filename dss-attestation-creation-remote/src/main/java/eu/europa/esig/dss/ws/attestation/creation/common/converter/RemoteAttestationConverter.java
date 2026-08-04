package eu.europa.esig.dss.ws.attestation.creation.common.converter;

import eu.europa.esig.dss.attestation.common.creation.AttestationDocument;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Converts a {@code AttestationDocument} to an instance of
 * {@code eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument}
 *
 */
@SuppressWarnings("rawtypes")
public class RemoteAttestationConverter {

    /**
     * Default constructor
     */
    private RemoteAttestationConverter() {
        // empty
    }

    /**
     * Converts an {@code AttestationDocument} to an instance of
     * {@code eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument}
     *
     * @param attestationDocument {@link AttestationDocument} to convert
     * @return {@link RemoteAttestationDocument}
     */
    @SuppressWarnings("unchecked")
    public static RemoteAttestationDocument toRemoteAttestationDocument(AttestationDocument attestationDocument) {
        final RemoteAttestationDocument remoteAttestationDocument = new RemoteAttestationDocument();
        RemoteDocument signedAttestation = RemoteDocumentConverter.toRemoteDocument(attestationDocument.getSignedAttestation());
        remoteAttestationDocument.setSignedAttestation(signedAttestation);
        List<DisclosureDTO> disclosureDTOs = ((List<SelectiveDisclosure>) attestationDocument.getSelectiveDisclosures())
                .stream().map(new DisclosureToDTOConverter()).collect(Collectors.toList());
        remoteAttestationDocument.setDisclosures(disclosureDTOs);
        return remoteAttestationDocument;
    }

}
