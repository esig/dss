package eu.europa.esig.dss.xades.dom;

import eu.europa.esig.dss.xades.definition.XAdESPath;
import org.w3c.dom.Element;

import java.util.List;

/**
 * This class represents a wrapper for a {@code org.w3c.dom.Element} object for a XAdES signature
 *
 */
public class XAdESDOMElement {

    /** Owner document */
    private final XAdESDOMDocument ownerDocument;

    /** XML DOM element */
    private final Element element;

    /**
     * Default constructor
     *
     * @param element {@link Element}
     * @param ownerDocument {@link XAdESDOMDocument}
     */
    public XAdESDOMElement(final Element element, final XAdESDOMDocument ownerDocument) {
        this.ownerDocument = ownerDocument;
        this.element = element;
    }

    /**
     * Gets the XML DOM Element
     *
     * @return {@link Element}
     */
    public Element getElement() {
        return element;
    }

    /**
     * Gets the owner document
     *
     * @return {@link XAdESDOMDocument}
     */
    public XAdESDOMDocument getOwnerDocument() {
        return ownerDocument;
    }

    /**
     * Gets a list of registered XAdES Path holders
     *
     * @return a list of {@link XAdESPath}s
     */
    public List<XAdESPath> getXAdESPathHolders() {
        return ownerDocument.getXAdESPathHolders();
    }

}
