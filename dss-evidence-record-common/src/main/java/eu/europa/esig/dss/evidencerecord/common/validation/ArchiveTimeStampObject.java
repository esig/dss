package eu.europa.esig.dss.evidencerecord.common.validation;

import java.util.List;

/**
 * Represents an Evidence Record's ArchiveTimeStamp object.
 * Contains the hash tree as well as the time-stamp binaries.
 */
public class ArchiveTimeStampObject implements EvidenceRecordObject {

    private static final long serialVersionUID = 5881635666028328980L;

    /** The ordered list of data object groups containing their digest values */
    private List<? extends DigestValueGroup> hashTree;

    /** Binaries of the time-stamp token */
    private byte[] timestampToken;

    /** The reference to the parent object */
    private ArchiveTimeStampChainObject parent;

    /**
     * Default constructor
     */
    public ArchiveTimeStampObject() {
        // empty
    }

    /**
     * Gets the ordered hash tree
     *
     * @return a list of {@link DigestValueGroup}s
     */
    public List<? extends DigestValueGroup> getHashTree() {
        return hashTree;
    }

    /**
     * Sets the ordered hash tree
     *
     * @param hashTree a list of {@link DigestValueGroup}s
     */
    public void setHashTree(List<? extends DigestValueGroup> hashTree) {
        this.hashTree = hashTree;
    }

    /**
     * Gets the time-stamp token binaries
     *
     * @return encoded time-stamp token
     */
    public byte[] getTimestampToken() {
        return timestampToken;
    }

    /**
     * Sets the time-stamp token binaries
     *
     * @param timestampToken byte array containing the encoded time-stamp token
     */
    public void setTimestampToken(byte[] timestampToken) {
        this.timestampToken = timestampToken;
    }

    /**
     * Gets the parent {@code ArchiveTimeStampChainObject}
     *
     * @return {@link ArchiveTimeStampChainObject}
     */
    public ArchiveTimeStampChainObject getParent() {
        return parent;
    }

    /**
     * Sets the parent {@code ArchiveTimeStampChainObject}
     *
     * @param parent {@link ArchiveTimeStampChainObject}
     */
    public void setParent(ArchiveTimeStampChainObject parent) {
        this.parent = parent;
    }

}
