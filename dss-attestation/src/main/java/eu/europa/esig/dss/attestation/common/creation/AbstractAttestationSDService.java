package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

/**
 * Abstract implementation of an attestation with selective disclosures creation service.
 *
 * @param <SP>
 *         implementation of attestation Claim for the attestation format
 * @param <P>
 *         implementation of attestation payload parameters to the attestation format
 * @param <D>
 *         implementation of attestation disclosure for the attestation format
 */
public abstract class AbstractAttestationSDService<SP extends SerializableSignatureParameters, P extends AttestationPayloadParameters,
        D extends SelectiveDisclosure> extends AbstractAttestationService<SP, P, AttestationSDPayloadBuilder<P, D>>
        implements AttestationSDService<SP, P, D> {

    private static final long serialVersionUID = -1605530972695706489L;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    protected AbstractAttestationSDService(CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
    }

}
