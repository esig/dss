package eu.europa.esig.dss.evidencerecord;

import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * Contains parameters used on Evidence Record incorporation within an existing signature
 *
 */
public abstract class AbstractEvidenceRecordIncorporationParameters {

    /**
     * Identifier of a signature to include the evidence record into
     */
    private String signatureId;

    /**
     * The detached documents signed by a signature
     */
    private List<DSSDocument> detachedContents;

    /**
     * Default constructor
     */
    protected AbstractEvidenceRecordIncorporationParameters() {
        // empty
    }

    /**
     * Gets an identifier of signature to include the evidence record into
     *
     * @return {@link String}
     */
    public String getSignatureId() {
        return signatureId;
    }

    /**
     * Sets an identifier of signature to include the evidence record into.
     * When a document with a single signature is provided, the value can be set to null.
     * Otherwise, the signature with the given identifier shall be found in order to perform the operation.
     *
     * @param signatureId {@link String}
     */
    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    /**
     * Gets detached documents signed by a signature
     *
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
    }

    /**
     * Sets detached documents signed by a signature
     *
     * @param detachedContents a list of {@link DSSDocument}s
     */
    public void setDetachedContents(List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

}
