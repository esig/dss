package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;

import java.util.List;

/**
 * Extension of {@link AttestationService} that supports selective disclosure.
 * <p>
 * This service is intended to be used by an attestation issuer that issues
 * credentials containing selectively disclosable claims. It extends the basic
 * attestation signing workflow with the generation and attachment of
 * disclosures corresponding to claims marked as selectively disclosable.
 * <p>
 * After the attestation has been signed, this service can generate
 * disclosures from the attestation payload and produce a resulting attestation
 * containing the attestation signature together with the associated disclosures.
 * <p>
 * The resulting attestation is intended to be transferred to a wallet,
 * where the holder can later decide which disclosures to present to a verifier.
 *
 * @param <SP>
 *           implementation of the signature parameters
 * @param <B>
 *           implementation of the payload parameters
 * @param <D>
 *           implementation of the selective disclosure representation
 */
public interface AttestationSDService<SP extends SerializableSignatureParameters, B extends AttestationPayloadParameters,
        D extends SelectiveDisclosure> extends AttestationService<SP, B> {

    /**
     * Generates disclosures for every claim marked as selectively disclosable in
     * the supplied payload parameters.
     * <p>
     * The returned disclosures can later be attached to the issued attestation
     * or selectively included in an attestation presentation.
     *
     * @param payloadParameters
     *             {@link AttestationPayloadParameters} payload definition
     * @return a list of generated {@link SelectiveDisclosure}s
     */
    List<D> generateDisclosures(final B payloadParameters);

    /**
     * Creates an issued attestation containing only the signed attestation without
     * any selective disclosures.
     *
     * @param signedAttestation
     *             {@link DSSDocument} signed attestation
     * @return {@link DSSDocument} issued attestation
     */
    DSSDocument issueAttestation(final DSSDocument signedAttestation);

    /**
     * Creates an issued attestation and automatically attaches all disclosures
     * generated from the supplied payload parameters.
     *
     * @param signedAttestation
     *             {@link DSSDocument} signed attestation
     * @param payloadParameters
     *             {@link AttestationPayloadParameters} payload definition used to generate disclosures
     * @return {@link DSSDocument} issued attestation containing all generated disclosures
     */
    DSSDocument issueAttestation(final DSSDocument signedAttestation, B payloadParameters);

    /**
     * Creates an issued attestation containing the supplied disclosures.
     *
     * @param signedAttestation
     *             {@link DSSDocument} signed attestation
     * @param disclosures
     *             a list of {@link SelectiveDisclosure}s to embed
     * @return {@link DSSDocument} issued attestation containing provided disclosures
     */
    DSSDocument issueAttestation(final DSSDocument signedAttestation, List<D> disclosures);

}
