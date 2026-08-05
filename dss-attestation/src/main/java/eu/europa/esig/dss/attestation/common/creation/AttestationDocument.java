package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;

import java.io.InputStream;
import java.util.List;
import java.util.Objects;

/**
 * Represents an attestation with selective disclosures document.
 * The class allows extraction of SD Attestation parts, such as a signed attestation or selective disclosures only.
 *
 */
public abstract class AttestationDocument<D extends SelectiveDisclosure> extends CommonDocument  {

    private static final long serialVersionUID = 2468430085298606741L;

    /** Attestation with selective disclosures document */
    private final DSSDocument attestationDocument;

    /** Signed attestation document (SDs omitted) */
    private final DSSDocument signedAttestation;

    /** List of selective disclosures */
    private final List<D> selectiveDisclosures;

    /**
     * Default constructor, instantiating the object from a complete SD Attestation,
     * signed attestation and selective disclosures parts.
     *
     * @param attestationDocument {@link DSSDocument} attestation with selective disclosures
     * @param signedAttestation {@link DSSDocument} signed attestation (SDs omitted)
     * @param selectiveDisclosures a list of {@link SelectiveDisclosure}s, if any
     */
    protected AttestationDocument(final DSSDocument attestationDocument, final DSSDocument signedAttestation,
                                  final List<D> selectiveDisclosures) {
        Objects.requireNonNull(attestationDocument, "SD Attestation cannot be null!");
        this.attestationDocument = attestationDocument;
        this.signedAttestation = signedAttestation;
        this.selectiveDisclosures = selectiveDisclosures;
    }

    /**
     * Gets the signed attestation (usually a signature), with selective disclosures omitted.
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getSignedAttestation() {
        return signedAttestation;
    }

    /**
     * Gets a list of selective disclosures, if any
     *
     * @return a list of {@link SelectiveDisclosure}s
     */
    public List<D> getSelectiveDisclosures() {
        return selectiveDisclosures;
    }

    @Override
    public InputStream openStream() {
        return attestationDocument.openStream();
    }

}
