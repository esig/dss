package eu.europa.esig.dss.xml.utils.xpath;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

/**
 * Executes XPath expression query based on the {@code javax.xml.xpath.XPathExpression} class.
 *
 */
public class JavaXmlXPathQueryExecutor extends AbstractXPathQueryExecutor implements XPathStringExecutor {

    /** The used XPathFactory */
    private static final XPathFactory factory = XPathFactory.newInstance();

    /**
     * Default constructor
     */
    public JavaXmlXPathQueryExecutor() {
        // empty
    }

    @Override
    public NodeList getNodeList(Node xmlNode, XPathQuery xPathQuery) {
        return getNodeList(xmlNode, xPathQuery.getQueryString());
    }

    /**
     * Returns the NodeList corresponding to the XPath query.
     *
     * @param xmlNode
     *                    The node where the search should be performed.
     * @param xPathString
     *                    {@link String} XPath query string
     * @return the NodeList corresponding to the XPath query
     */
    @Override
    public NodeList getNodeList(Node xmlNode, String xPathString) {
        try {
            final XPathExpression expr = createXPathExpression(xPathString);
            return (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            throw new DSSException(String.format("Unable to find a NodeList by the given xPathString '%s'. Reason : %s",
                    xPathString, e.getMessage()), e);
        }
    }

    /**
     * This method creates a new instance of XPathExpression with the given xpath query
     *
     * @param xpathString {@link String} representing the XPath expression to be executed
     * @return an instance of {@code XPathExpression} for the given xpathString
     */
    protected XPathExpression createXPathExpression(final String xpathString) {
        final XPath xpath = factory.newXPath();
        if (namespaceContext != null) {
            xpath.setNamespaceContext(namespaceContext);
        }
        try {
            return xpath.compile(xpathString);
        } catch (XPathExpressionException e) {
            throw new DSSException(String.format("Unable to create an XPath expression : %s", e.getMessage()), e);
        }
    }

}
