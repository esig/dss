package eu.europa.esig.dss.xml.common.xpath.item;

import org.w3c.dom.Node;

/**
 * XPath expression chain item corresponding to an any element within the path
 *
 */
public class XPathQueryAnyItem extends AbstractXPathQueryItem {

    /** Any path */
    private static final String ANY_PATH = "*";

    /**
     * Default constructor
     */
    public XPathQueryAnyItem() {
        // empty
    }

    @Override
    protected boolean process(Node node) {
        return Node.ELEMENT_NODE == node.getNodeType();
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
        return ANY_PATH;
    }

}
