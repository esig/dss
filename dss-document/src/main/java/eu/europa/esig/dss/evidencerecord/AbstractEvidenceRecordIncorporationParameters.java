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
     * Defines whether the new evidence-record shall be added to the last available evidence-record attribute,
     * when present. Otherwise, the hash will be computed based on the whole document content (default behavior).
     */
    private boolean parallelEvidenceRecord;

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

    /**
     * Gets whether the evidence record should be incorporated within an existing (latest) evidence-record unsigned property,
     * when available. Otherwise, a new evidence record attribute is to be created for incorporation of the evidence record.
     *
     * @return whether the evidence record should be included in the existing (latest) evidence-record unsigned property
     */
    public boolean isParallelEvidenceRecord() {
        return parallelEvidenceRecord;
    }

    /**
     * Sets whether the evidence record should be incorporated within an existing (latest) evidence-record unsigned property,
     * when available. Otherwise, a new evidence record attribute is to be created for incorporation of the evidence record.
     * <p>
     * Default : FALSE (a new evidence record unsigned property is to be created)
     *
     * @param parallelEvidenceRecord whether the evidence record should be included in
     *                               the existing (latest) evidence-record unsigned property
     */
    public void setParallelEvidenceRecord(boolean parallelEvidenceRecord) {
        this.parallelEvidenceRecord = parallelEvidenceRecord;
    }

}
