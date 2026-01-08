package eu.europa.esig.dss.xml.utils.xpath;

import eu.europa.esig.dss.xml.utils.NamespaceContextMap;

/**
 * Abstract implementation of an {@code XPathQueryExecutor} containing common methods and utilities.
 *
 */
public abstract class AbstractXPathQueryExecutor implements XPathQueryExecutor {

    /** Map containing the defined namespaces */
    protected NamespaceContextMap namespaceContext;

    /**
     * Default constructor
     */
    protected AbstractXPathQueryExecutor() {
        // empty
    }

    @Override
    public void setNamespaceContext(NamespaceContextMap namespaceContext) {
        this.namespaceContext = namespaceContext;
    }

}
