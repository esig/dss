package eu.europa.esig.dss.xml.common.xpath.item;

import org.w3c.dom.Node;

import java.util.Collections;
import java.util.List;

/**
 * This XPath Query item is used to indicate the end of an XPath expression.
 * The use of the item is optional, and it does not impact the XPath Query processing,
 * but does not allow extension of the XPath Query with other rules or items.
 *
 */
public class XPathQueryEndItem implements XPathQueryItem {

    /**
     * Default constructor
     */
    public XPathQueryEndItem() {
        // empty
    }

    @Override
    public XPathQueryItem nextItem() {
        return null;
    }

    @Override
    public XPathQueryItem setNextItem(XPathQueryItem nextItem) {
        throw new UnsupportedOperationException("Unable to continue XPath query after the XPathQueryEnd item.");
    }

    @Override
    public boolean matchNode(Node node) {
        return true;
    }

    @Override
    public void addParameter(XPathQueryParameter parameter) {
        throw new UnsupportedOperationException("Unable to add parameters to the XPathQueryEnd item.");
    }

    @Override
    public List<XPathQueryParameter> getParameters() {
        return Collections.emptyList();
    }

    @Override
    public boolean isElementRelated() {
        return true;
    }

    @Override
    public boolean isAttributeRelated() {
        return true;
    }

    @Override
    public boolean isEmpty() {
        return true;
    }

    @Override
    public String getQueryString() {
        return "";
    }

}
