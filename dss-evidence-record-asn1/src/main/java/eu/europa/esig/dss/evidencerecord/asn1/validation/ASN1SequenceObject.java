package eu.europa.esig.dss.evidencerecord.asn1.validation;

import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.w3c.dom.Element;

import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;

public class ASN1SequenceObject extends DigestValueGroup implements ASN1EvidenceRecordObject {

	private static final long serialVersionUID = -747779213316560098L;

	/** The current Element */
    private final PartialHashtree element;

    /** Order of the element */
    private int order;

    /**
     * Default constructor
     *
     * @param element {@link Element}
     */
    public ASN1SequenceObject(final PartialHashtree element) {
        this.element = element;
    }

//    @Override
//    public Element getElement() {
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