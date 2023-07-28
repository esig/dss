package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import org.w3c.dom.Element;

/**
 * Ths Xml Evidence Record representation of Sequence element
 *
 */
public class XmlSequenceObject extends DigestValueGroup implements XmlEvidenceRecordObject {

    private static final long serialVersionUID = 1654026857925915911L;

    /** The current Element */
    private final Element element;

    /** Order of the element */
    private int order;

    /**
     * Default constructor
     *
     * @param element {@link Element}
     */
    public XmlSequenceObject(final Element element) {
        this.element = element;
    }

    @Override
    public Element getElement() {
        return element;
    }

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
