package eu.europa.esig.dss.xml.common.xpath;

import eu.europa.esig.dss.xml.common.xpath.item.XPathQueryItem;

/**
 * This class represents an XPath expression query, ready for the execution on an XML DOM.
 *
 */
public interface XPathQuery {

    /**
     * Gets the first part of the XPath expression (usually the first element of the XPath string)
     *
     * @return {@link XPathQueryItem}
     */
    XPathQueryItem getFirstXPathQueryItem();

    /**
     * Gets whether all descendants matching the XPath expression are to be returned.
     * If FALSE, only the children of the current element matching the XPath expression are extracted.
     *
     * @return whether all descendants matching the XPath expression are to be returned
     */
    boolean isAll();

    /**
     * Gets whether the XPath expression execution starts from a node at the current position.
     * if FALSE, the execution starts from the root element of the XML document.
     *
     * @return whether the XPath expression execution starts from a node at the current position
     */
    boolean isFromCurrentPosition();

    /**
     * Returns whether the XPath expression contains any XPath item definitions
     *
     * @return TRUE if the XPath expression is empty, FALSE otherwise
     */
    boolean isEmpty();

    /**
     * Sets the next {@code eu.europa.esig.dss.xml.common.definition.xpath.item.XPathItem}
     * as part of the XPath expression
     *
     * @param nextItem {@link XPathQueryItem} to set
     * @return this {@link XPathQuery}
     */
    XPathQuery setNextItem(XPathQueryItem nextItem);

    /**
     * Gets a string representation of the XPath expression
     *
     * @return {@link String}
     */
    String getQueryString();

}
