package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.util.List;

/**
 * Represents an ArchiveTimeStampChain object incorporated within an Evidence Record
 */
public class ArchiveTimeStampChainObject implements EvidenceRecordObject {

    private static final long serialVersionUID = -981112646470456626L;

    /** Digest algorithm used for digest computation of data objects */
    private DigestAlgorithm digestAlgorithm;

    /** List of ordered ArchiveTimeStamp objects */
    private List<? extends ArchiveTimeStampObject> archiveTimeStamps;

    /** Order of the element */
    private int order;

    /**
     * Default constructor
     */
    public ArchiveTimeStampChainObject() {
        // empty
    }

    /**
     * Gets DigestAlgorithm used for digest of data objects generation
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Sets DigestAlgorithm used on data objects' digest generation
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Gets an ordered list of archive time-stamp data objects
     *
     * @return a list of {@link ArchiveTimeStampObject}s
     */
    public List<? extends ArchiveTimeStampObject> getArchiveTimeStamps() {
        return archiveTimeStamps;
    }

    /**
     * Sets an ordered list of archive time-stamp data objects
     *
     * @param archiveTimeStamps a list of {@link ArchiveTimeStampObject}s
     */
    public void setArchiveTimeStamps(List<? extends ArchiveTimeStampObject> archiveTimeStamps) {
        this.archiveTimeStamps = archiveTimeStamps;
    }

    /**
     * Gets Order attribute value of the corresponding element
     *
     * @return Order attribute value
     */
    public int getOrder() {
        return order;
    }

    /**
     * Sets order of the object within its parent
     *
     * @param order int value
     */
    public void setOrder(int order) {
        this.order = order;
    }

}
