package eu.europa.esig.dss.xml.utils.xpath;

import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import eu.europa.esig.dss.xml.utils.NamespaceContextMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * This class executes the given {@code eu.europa.esig.dss.xml.common.xpath.XPathQuery}.
 *
 */
public interface XPathQueryExecutor {

    /**
     * Sets the namespace context map containing a declaration of namespaces defined within the used XPath expressions
     *
     * @param namespaceContext {@link NamespaceContextMap}
     */
    void setNamespaceContext(NamespaceContextMap namespaceContext);

    /**
     * Returns the NodeList corresponding to the XPath query.
     *
     * @param xmlNode
     *                    The node where the search should be performed.
     * @param xPathQuery
     *                    {@link XPathQuery}
     * @return the NodeList corresponding to the XPath query
     */
    NodeList getNodeList(final Node xmlNode, final XPathQuery xPathQuery);

}
