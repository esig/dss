package eu.europa.esig.dss.xml.common.xpath.item;

import eu.europa.esig.dss.xml.common.definition.DSSAttribute;
import org.w3c.dom.Node;

import java.util.Objects;

/**
 * Gets XPath expression item allowing to access an attribute value of the current element.
 * This class is normally used for attribute value extraction, as an alternative to {@code XPathQueryByAttribute}
 *
 */
public class XPathQueryAttributeItem extends AbstractXPathQueryItem {

    /** Defines an attribute value */
    private static final String ATTRIBUTE_PATH = "@";

    /** Attribute which value is to be accessed */
    private final DSSAttribute attribute;

    /**
     * Default constructor to extract an element containing the given attribute (any value is accepted)
     *
     * @param attribute {@link DSSAttribute}
     */
    public XPathQueryAttributeItem(final DSSAttribute attribute) {
        Objects.requireNonNull(attribute, "Attribute cannot be null!");
        this.attribute = attribute;
    }

    /**
     * Gets the corresponding DSSAttribute
     *
     * @return {@link DSSAttribute}
     */
    public DSSAttribute getAttribute() {
        return attribute;
    }

    @Override
    protected boolean process(Node node) {
        if (Node.ATTRIBUTE_NODE == node.getNodeType()) {
            return attribute.getAttributeName().equals(getLocalName(node));
        }
        return false;
    }

    @Override
    public boolean isElementRelated() {
        return false;
    }

    @Override
    public boolean isAttributeRelated() {
        return true;
    }

    @Override
    public String getQueryString() {
        return ATTRIBUTE_PATH + attribute.getAttributeName();
    }

}
