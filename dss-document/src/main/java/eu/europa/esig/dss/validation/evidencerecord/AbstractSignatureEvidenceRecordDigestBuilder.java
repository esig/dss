package eu.europa.esig.dss.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;

import java.util.Objects;

/**
 * Abstract implementation of the {@code SignatureEvidenceRecordDigestGenerator}
 *
 */
public abstract class AbstractSignatureEvidenceRecordDigestBuilder implements SignatureEvidenceRecordDigestBuilder {

    /**
     * Signature document to compute hash value for
     */
    protected final DSSDocument signatureDocument;

    /**
     * The digest algorithm to be used on hash computation.
     * Default : DigestAlgorithm.SHA256
     */
    protected final DigestAlgorithm digestAlgorithm;

    /**
     * Defines whether the new evidence-record shall be added to the last available evidence-record attribute,
     * when present. Otherwise, the hash will be computed based on the whole document content (default behavior).
     */
    protected boolean parallelEvidenceRecord;

    /**
     * Default constructor to instantiate builder with a SHA-256 digest algorithm
     *
     * @param signatureDocument {@link DSSDocument} to compute message-imprint for
     */
    protected AbstractSignatureEvidenceRecordDigestBuilder(final DSSDocument signatureDocument) {
        this(signatureDocument, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to instantiate builder with a custom digest algorithm
     *
     * @param signatureDocument {@link DSSDocument} to compute message-imprint for
     * @param digestAlgorithm {@link DigestAlgorithm} to be used
     */
    protected AbstractSignatureEvidenceRecordDigestBuilder(final DSSDocument signatureDocument, final DigestAlgorithm digestAlgorithm) {
        Objects.requireNonNull(signatureDocument, "Signature document cannot be null!");
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
        this.signatureDocument = signatureDocument;
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Sets whether the message-imprint for an evidence record shall be computed as for a parallel evidence-record
     * (i.e. to be incorporated within the latest evidence-record attribute, when available). Otherwise, will compute
     * message-imprint based on the whole signature's content, including coverage of other existing evidence-record.
     * Default : FALSE (computes digest based on the whole signature's content)
     *
     * @param parallelEvidenceRecord whether the message-imprint for an evidence record shall be computed as for a parallel evidence-record
     * @return this builder
     */
    public AbstractSignatureEvidenceRecordDigestBuilder setParallelEvidenceRecord(boolean parallelEvidenceRecord) {
        this.parallelEvidenceRecord = parallelEvidenceRecord;
        return this;
    }

    /**
     * Returns digest of the given document
     *
     * @param document {@link DSSDocument} to compute digest for
     * @return {@link Digest}
     */
    protected Digest getDigest(DSSDocument document) {
        return new Digest(digestAlgorithm, document.getDigestValue(digestAlgorithm));
    }

}
