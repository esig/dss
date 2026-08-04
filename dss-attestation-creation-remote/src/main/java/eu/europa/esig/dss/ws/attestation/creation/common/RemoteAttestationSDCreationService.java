package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

/**
 * Remote service to sign an attestation (e.g. EAA, PID, etc.) containing selectively disclosable claims,
 * and issue the attestations token
 *
 */
public interface RemoteAttestationSDCreationService extends RemoteAttestationCreationService {

    /**
     * Generates disclosures for every claim marked as selectively disclosable in
     * the supplied payload parameters.
     * <p>
     * The returned disclosures can later be attached to the issued attestation
     * or selectively included in an attestation presentation.
     *
     * @param payloadParameters
     *             {@link RemoteAttestationPayloadParameters} payload definition
     * @return a list of generated {@link DisclosureDTO}s
     */
    List<DisclosureDTO> generateDisclosures(final RemoteAttestationPayloadParameters payloadParameters);

    /**
     * Creates an issued attestation and automatically attaches all disclosures
     * generated from the supplied payload parameters or uses the provided disclosures.
     * NOTE: when a list of disclosures is provided, the list will be used instead of payload parameters.
     * For an attestation without disclosures, please define an empty list of disclosures.
     *
     * @param signedAttestation
     *             {@link RemoteDocument} signed attestation
     * @param payloadParameters
     *             {@link RemoteAttestationPayloadParameters} payload definition used to generate disclosures
     * @param disclosures
     *             (Optional) a list of {@link DisclosureDTO}s to embed
     * @return {@link RemoteDocument} issued attestation containing all generated disclosures
     */
    RemoteDocument issueAttestation(final RemoteDocument signedAttestation, final RemoteAttestationPayloadParameters payloadParameters,
                                    final List<DisclosureDTO> disclosures);

}
