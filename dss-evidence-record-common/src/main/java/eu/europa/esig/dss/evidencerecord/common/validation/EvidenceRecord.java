package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.ArrayList;
import java.util.List;

/**
 * Default representation of an Evidence Record
 *
 */
public abstract class EvidenceRecord {

    /**
     * The name of the evidence record document
     */
    private String filename;

    /**
     * Contains a list of documents time-stamped within a reduced HashTree
     */
    private List<DSSDocument> detachedContents = new ArrayList<>();

    /** Represents a structure of the evidence record */
    private List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence;

    /** Cached result of archive data objects validation */
    protected List<ReferenceValidation> referenceValidations;

    /**
     * Default constructor
     */
    protected EvidenceRecord() {
        // empty
    }

    /**
     * Gets the evidence record filename
     *
     * @return {@link String}
     */
    public String getFilename() {
        return filename;
    }

    /**
     * Sets the evidence record filename
     *
     * @param filename {@link String}
     */
    public void setFilename(String filename) {
        this.filename = filename;
    }

    /**
     * Returns a list of provided detached documents covered by the Evidence Record
     *
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
    }

    /**
     * Sets a list of detached documents covered by the reduced HashTree of the Evidence Record
     *
     * @param detachedContents a list of {@link DSSDocument}s
     */
    public void setDetachedContents(final List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    /**
     * Gets an archive time-stamp sequence
     *
     * @return a list of {@link ArchiveTimeStampChainObject}s
     */
    public List<? extends ArchiveTimeStampChainObject> getArchiveTimeStampSequence() {
        if (archiveTimeStampSequence == null) {
            archiveTimeStampSequence = buildArchiveTimeStampSequence();
        }
        return archiveTimeStampSequence;
    }

    /**
     * Build an archive time-stamp sequence
     *
     * @return a list of ordered {@link ArchiveTimeStampChainObject}s
     */
    protected abstract List<? extends ArchiveTimeStampChainObject> buildArchiveTimeStampSequence();

    /**
     * Returns a list of incorporated timestamp tokens
     *
     * @return a list of {@link TimestampToken}s
     */
    public List<TimestampToken> getTimestamps() {
        return getTimestampSource().getTimestamps();
    }

    /**
     * Gets a Timestamp source which contains ALL timestamps embedded in the evidence record.
     *
     * @return {@code EvidenceRecordTimestampSource}
     */
    public abstract EvidenceRecordTimestampSource<?> getTimestampSource();

    /**
     * Performs validation of the detached content and returns back the validity results
     *
     * @return a list of {@link ReferenceValidation} objects corresponding to each archive data object validation
     */
    public abstract List<ReferenceValidation> getReferenceValidation();

    /**
     * This method is used to verify the structure of the evidence record document
     *
     * @return a list of {@link String} errors when applicable
     */
    public abstract List<String> validateStructure();


}
