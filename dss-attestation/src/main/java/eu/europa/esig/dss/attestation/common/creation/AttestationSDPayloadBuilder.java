package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;

import java.util.List;

/**
 * Builds attestation builder based on the provided configuration,
 * including the list of selective disclosures, when applicable.
 *
 * @param <P> implementation of {@link AttestationPayloadParameters} for the attestation format
 * @param <D> implementation of {@link SelectiveDisclosure} for the attestation format
 */
public interface AttestationSDPayloadBuilder<P extends AttestationPayloadParameters, D extends SelectiveDisclosure>
        extends AttestationPayloadBuilder<P> {

    /**
     * Builds a list of selectively disclosable attestation claims to be used for Digest computation, format specific
     *
     * @param payloadParameters {@link AttestationPayloadParameters}
     * @return {@link SelectiveDisclosure} representing the disclosure structure
     */
    List<D> buildDisclosures(P payloadParameters);

}
