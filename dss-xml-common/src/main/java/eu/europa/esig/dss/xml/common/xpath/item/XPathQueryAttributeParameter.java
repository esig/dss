package eu.europa.esig.dss.xml.common.xpath.item;

import eu.europa.esig.dss.xml.common.definition.DSSAttribute;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.util.Objects;

/**
 * Allows extraction of an element by the given attribute
 *
 */
public class XPathQueryAttributeParameter extends AbstractXPathQueryParameter {

    /** Attribute */
    private final DSSAttribute attribute;

    /** Value of the attribute */
    private final String attributeValue;

    /** Whether the case comparison on attribute name is to be ignored */
    private final boolean ignoreCase;

    /**
     * Constructor with an expected attribute value.
     * When this constructor is used, the string case comparison is enforced.
     *
     * @param attribute {@link DSSAttribute}
     * @param attributeValue {@link String}
     */
    public XPathQueryAttributeParameter(final DSSAttribute attribute, final String attributeValue) {
        this(attribute, attributeValue, false);
    }

    /**
     * Constructor with an expected attribute value with indication on whether case is to be ignored
     *
     * @param attribute {@link DSSAttribute}
     * @param attributeValue {@link String}
     * @param ignoreCase whether case comparison of the attribute name is to be ignored
     */
    public XPathQueryAttributeParameter(final DSSAttribute attribute, final String attributeValue, final boolean ignoreCase) {
        Objects.requireNonNull(attribute, "DSSAttribute cannot be null!");
        Objects.requireNonNull(attributeValue, "Attribute value cannot be null!");
        this.attribute = attribute;
        this.attributeValue = attributeValue;
        this.ignoreCase = ignoreCase;
    }

    /**
     * Gets the corresponding DSSAttribute
     *
     * @return {@link DSSAttribute}
     */
    public DSSAttribute getAttribute() {
        return attribute;
    }

    /**
     * Gets the expected attribute value
     *
     * @return {@link String}
     */
    public String getAttributeValue() {
        return attributeValue;
    }

    @Override
    protected boolean process(Node node) {
        if (Node.ELEMENT_NODE == node.getNodeType()) {
            Element element = (Element) node;
            NamedNodeMap attributes = element.getAttributes();
            if (attributes != null && attributes.getLength() > 0) {
                for (int i = 0; i < attributes.getLength(); i++) {
                    Node attributeNode = attributes.item(i);
                    boolean attributeNameMatch = ignoreCase ?
                            attribute.getAttributeName().equalsIgnoreCase(getLocalName(attributeNode)) :
                            attribute.getAttributeName().equals(getLocalName(attributeNode));
                    if (attributeNameMatch) {
                        String nodeValue = attributeNode.getNodeValue();
                        if (attributeValue.equals(nodeValue)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override
    public boolean isElementRelated() {
        return true;
    }

    @Override
    public boolean isAttributeRelated() {
        return false;
    }

    @Override
    public String getQueryString() {
        StringBuilder sb = new StringBuilder();
        addQueryForAttributeWithName(sb, attribute.getAttributeName());
        if (ignoreCase) {
            sb.append(" or ");
            addQueryForAttributeWithName(sb, attribute.getAttributeName().toLowerCase());
            sb.append(" or ");
            addQueryForAttributeWithName(sb, attribute.getAttributeName().toUpperCase());
        }
        return sb.toString();
    }

    private void addQueryForAttributeWithName(StringBuilder sb, String attrName) {
        sb.append("@*[local-name()='");
        sb.append(attrName);
        sb.append("']");
        if (attributeValue != null) {
            sb.append("='");
            sb.append(attributeValue);
            sb.append("'");
        }
    }

}
