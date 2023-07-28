package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import org.w3c.dom.Element;

/**
 * Ths Xml Evidence Record representation of ArchiveTimeStamp element
 *
 */
public class XmlArchiveTimeStampObject extends ArchiveTimeStampObject implements XmlEvidenceRecordObject {

    private static final long serialVersionUID = 4575300094126130628L;

    /** The current Element */
    private final Element element;

    /** Order of the element */
    private int order;

    /**
     * Default constructor
     *
     * @param element {@link Element}
     */
    public XmlArchiveTimeStampObject(final Element element) {
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
