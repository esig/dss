package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.attestation.common.creation.AttestationDocument;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * SD-JWT implementation of an annotation document, containing the signed JWT and the applicable selective disclosures
 *
 */
public class SDJWTAttestationDocument extends AttestationDocument<SDJWTSelectiveDisclosure> {

    private static final long serialVersionUID = 5572839736743454415L;

    /**
     * Default constructor, instantiating the object from a complete SD Attestation,
     * signed attestation and selective disclosures parts.
     *
     * @param attestationDocument  {@link DSSDocument} attestation with selective disclosures
     * @param signedAttestation    {@link DSSDocument} signed attestation (SDs omitted)
     * @param selectiveDisclosures a list of {@link SDJWTSelectiveDisclosure}s, if any
     */
    public SDJWTAttestationDocument(DSSDocument attestationDocument, DSSDocument signedAttestation,
                                    List<SDJWTSelectiveDisclosure> selectiveDisclosures) {
        super(attestationDocument, signedAttestation, selectiveDisclosures);
    }

}
