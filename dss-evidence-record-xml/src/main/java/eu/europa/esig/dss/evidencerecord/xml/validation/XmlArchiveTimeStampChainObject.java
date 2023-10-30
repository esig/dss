package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import org.w3c.dom.Element;

/**
 * Ths Xml Evidence Record representation of ArchiveTimeStampChain element
 *
 */
public class XmlArchiveTimeStampChainObject extends ArchiveTimeStampChainObject implements XmlEvidenceRecordObject {

    private static final long serialVersionUID = -7472251015176736731L;

    /** The current Element */
    private final Element element;

    /** Canonicalization method (XML only) */
    private String canonicalizationMethod;

    /**
     * Default constructor
     *
     * @param element {@link Element}
     */
    public XmlArchiveTimeStampChainObject(final Element element) {
        this.element = element;
    }

    @Override
    public Element getElement() {
        return element;
    }

    /**
     * Gets canonicalization method (XML only)
     *
     * @return {@link String} representing the canonicalization algorithm
     */
    public String getCanonicalizationMethod() {
        return canonicalizationMethod;
    }

    /**
     * Sets canonicalization method (XML only)
     *
     * @param canonicalizationMethod {@link String} representing the canonicalization algorithm
     */
    public void setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
    }

}
