package eu.europa.esig.dss.xml.common.xpath.item;

import eu.europa.esig.dss.xml.common.definition.DSSElement;
import org.w3c.dom.Node;

import java.util.Objects;

/**
 * Represents an item within an XPath expression filtering out elements with a particular parent element.
 *
 */
public class XPathQueryNotChildOfParameter extends AbstractXPathQueryParameter {

    /** The beginning string of the "not child of" condition */
    private static final String NOT_PARENT_CONDITION_START = "not(parent::";

    /** The end string of the "not child of" condition */
    private static final String NOT_PARENT_CONDITION_END = ")";

    /**
     * Element item representing the parent element, the current element shall not belong to
     */
    private final XPathQueryElementItem elementItem;

    /**
     * Default constructor
     *
     * @param parentElement {@link DSSElement} to be avoided
     */
    public XPathQueryNotChildOfParameter(final DSSElement parentElement) {
        Objects.requireNonNull(parentElement, "Parent element cannot be null!");
        this.elementItem = new XPathQueryElementItem(parentElement);
    }

    /**
     * Gets the parent element to be avoided
     *
     * @return {@link DSSElement}
     */
    public DSSElement getParentElement() {
        return elementItem.getElement();
    }

    @Override
    protected boolean process(Node node) {
        if (Node.ELEMENT_NODE == node.getNodeType()) {
            Node parentNode = node.getParentNode();
            while (parentNode != null) {
                if (elementItem.matchNode(parentNode)) {
                    return false;
                }
                parentNode = parentNode.getParentNode();
            }
            return true;
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
        return NOT_PARENT_CONDITION_START + elementItem.getQueryString() + NOT_PARENT_CONDITION_END;
    }

}
