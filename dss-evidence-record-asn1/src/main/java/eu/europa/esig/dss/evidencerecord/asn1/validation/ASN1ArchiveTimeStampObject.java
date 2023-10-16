package eu.europa.esig.dss.evidencerecord.asn1.validation;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;

/**
 * The ASN1 Evidence Record representation of ArchiveTimeStamp element
 *
 */
public class ASN1ArchiveTimeStampObject extends ArchiveTimeStampObject implements ASN1EvidenceRecordObject {
    
	private static final long serialVersionUID = 2496285566554079215L;

	/** The current Element */
    private final ArchiveTimeStamp element;

    /** Order of the element */
    private int order;

    /**
     * Default constructor
     *
     * @param element {@link Element}
     */
    public ASN1ArchiveTimeStampObject(final ArchiveTimeStamp element) {
        this.element = element;
    }

//    @Override
//    public ArchiveTimeStamp getElement() {
//        return element;
//    }

    @Override
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
