package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.attestation.common.creation.AttestationDocument;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * Mdoc implementation of an attestation document, represented by an IssuerSigned structure object
 *
 */
public class MdocIssuerSignedDocument extends AttestationDocument<MdocIssuerSignedItem> {

    private static final long serialVersionUID = 4290289961894448368L;

    /**
     * Default constructor, instantiating the object from a complete SD Attestation,
     * signed attestation and selective disclosures parts.
     *
     * @param attestationDocument  {@link DSSDocument} attestation with selective disclosures
     * @param signedAttestation    {@link DSSDocument} signed attestation (SDs omitted)
     * @param selectiveDisclosures a list of {@link MdocIssuerSignedItem}s, if any
     */
    public MdocIssuerSignedDocument(DSSDocument attestationDocument, DSSDocument signedAttestation,
                                    List<MdocIssuerSignedItem> selectiveDisclosures) {
        super(attestationDocument, signedAttestation, selectiveDisclosures);
    }

}
