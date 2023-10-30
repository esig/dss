package eu.europa.esig.dss.evidencerecord.common.validation;

import java.util.List;

/**
 * Represents a Sequence/partialHashTree object, containing digest values of data objects
 *
 */
public class DigestValueGroup implements EvidenceRecordObject {

    private static final long serialVersionUID = 7059923281851256443L;

    /** List of digest values */
    private List<byte[]> digestValues;

    /** Order of the element */
    private int order;

    /**
     * Default constructor
     */
    public DigestValueGroup() {
        // empty
    }

    /**
     * Gets all digest values of the group
     *
     * @return a list of byte arrays representing digest values
     */
    public List<byte[]> getDigestValues() {
        return digestValues;
    }

    /**
     * Sets all digest values of the group of data objects
     *
     * @param digestValues a list of digest values
     */
    public void setDigestValues(List<byte[]> digestValues) {
        this.digestValues = digestValues;
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
