package eu.europa.esig.dss.xml.common.xpath.item;

import org.w3c.dom.Node;

import java.util.List;

/**
 * Represents a single XPath expression item.
 *
 */
public interface XPathQueryItem {

    /**
     * Gets the next XPath chain item, if any
     *
     * @return {@link XPathQueryItem} if next chain item is present, FALSE otherwise
     */
    XPathQueryItem nextItem();

    /**
     * Sets the next {@code eu.europa.esig.dss.xml.common.definition.xpath.item.XPathChainItem}
     * as part of the XPath expression
     *
     * @param nextItem {@link XPathQueryItem} to set
     * @return {@link XPathQueryItem} that has been set
     */
    XPathQueryItem setNextItem(XPathQueryItem nextItem);

    /**
     * This method verifies whether the given {@code node} matches the XPathQueryItem
     *
     * @param node {@link Node} to be evaluated against the XPath Query Item
     * @return TRUE if the Node matches the value, FALSE otherwise
     */
    boolean matchNode(Node node);

    /**
     * Adds a parameter to the given XPath query item
     *
     * @param parameter {@link XPathQueryParameter}
     */
    void addParameter(XPathQueryParameter parameter);

    /**
     * Gets parameters related to the given XPathQueryItem, if any
     *
     * @return a list of {@link XPathQueryParameter}s
     */
    List<XPathQueryParameter> getParameters();

    /**
     * Gets whether XPath query item is related to an Element node processing
     *
     * @return TRUE if XPath query item is related to an Element node processing, FALSE otherwise
     */
    boolean isElementRelated();

    /**
     * Gets whether XPath query item is related to an Attribute node processing
     *
     * @return TRUE if XPath query item is related to an Attribute node processing, FALSE otherwise
     */
    boolean isAttributeRelated();

    /**
     * Gets whether the XPath query item is empty
     *
     * @return TRUE if the XPath query item is empty, FALSE otherwise
     */
    boolean isEmpty();

    /**
     * Gets a string representation of the XPath expression chain item
     *
     * @return {@link String}
     */
    String getQueryString();

}
