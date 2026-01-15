package eu.europa.esig.dss.xml.utils.xpath;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import eu.europa.esig.dss.xml.common.xpath.XPathQueryBuilder;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.NamespaceContextMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 * This class contains utility methods for XPath execution, such as NodeList extraction, etc.
 *
 */
public final class XPathUtils {

    private static final Logger LOG = LoggerFactory.getLogger(XPathUtils.class);

    /** The default namespace prefix */
    private static final String XMLNS = "xmlns";

    /** Map containing the defined namespaces */
    private static final NamespaceContextMap namespacePrefixMapper;

    /** XPath query executor loader */
    private static XPathQueryExecutorLoader xPathQueryExecutorLoader;

    static {
        namespacePrefixMapper = new NamespaceContextMap();
        xPathQueryExecutorLoader = new XPathQueryExecutorLoader();
    }

    /**
     * Utils class
     */
    private XPathUtils() {
        // empty
    }

    /**
     * Gets the XPath Query executor
     *
     * @return {@link XPathQueryExecutor}
     */
    public static XPathQueryExecutor getXPathQueryExecutor() {
        XPathQueryExecutor executor = xPathQueryExecutorLoader.getXPathQueryExecutor();
        executor.setNamespaceContext(namespacePrefixMapper);
        return executor;
    }

    /**
     * Sets the XPathQueryExecutor to be used by the implementation.
     * This method also sets a namespace context to the executor defined within the implementation.
     * Default : Loads implementation accessible through ServiceLoader mechanism.
     *
     * @param xPathQueryExecutor {@link XPathQueryExecutor}
     */
    public static void setXPathQueryExecutor(XPathQueryExecutor xPathQueryExecutor) {
        xPathQueryExecutorLoader.setXPathQueryExecutor(xPathQueryExecutor);
    }

    /**
     * This method allows to register a namespace and associated prefix. If the prefix exists already it is replaced.
     *
     * @param namespace
     *            namespace object with the prefix and the URI
     * @return true if this map did not already contain the specified element
     */
    public static boolean registerNamespace(final DSSNamespace namespace) {
        final String prefix = namespace.getPrefix();
        final String uri = namespace.getUri();
        if (Utils.isStringEmpty(prefix)) {
            throw new UnsupportedOperationException("The empty namespace cannot be registered!");
        }
        if (XMLNS.equals(prefix)) {
            throw new UnsupportedOperationException(String.format("The default namespace '%s' cannot be registered!", XMLNS));
        }
        return namespacePrefixMapper.registerNamespace(prefix, uri);
    }

    /**
     * This method returns stored namespace definitions map
     *
     * @return {@link NamespaceContextMap} a map with the prefix and the related URI
     */
    public static NamespaceContextMap getNamespaceContextMap() {
        return namespacePrefixMapper;
    }

    /**
     * Returns the String value of the corresponding to the XPath query.
     *
     * @param xmlNode
     *                    The node where the search should be performed.
     * @param xPathQuery
     *                    {@link XPathQuery}
     * @return string value of the XPath query
     */
    public static String getValue(final Node xmlNode, final XPathQuery xPathQuery) {
        Node node = getNode(xmlNode, xPathQuery);
        if (node != null) {
            String string = node.getTextContent();
            return Utils.trim(string);
        }
        return null;
    }

    /**
     * Returns the NodeList corresponding to the XPath query.
     *
     * @param xmlNode
     *                    The node where the search should be performed.
     * @param xPathQuery
     *                    {@link XPathQuery}
     * @return the NodeList corresponding to the XPath query
     */
    public static NodeList getNodeList(final Node xmlNode, final XPathQuery xPathQuery) {
        return getXPathQueryExecutor().getNodeList(xmlNode, xPathQuery);
    }

    /**
     * Returns the Node corresponding to the XPath query.
     *
     * @param xmlNode
     *            The node where the search should be performed.
     * @param xPathQuery
     *            {@link XPathQuery}
     * @return the Node corresponding to the XPath query.
     */
    public static Node getNode(final Node xmlNode, final XPathQuery xPathQuery) {
        final NodeList list = getNodeList(xmlNode, xPathQuery);
        if (list.getLength() > 1) {
            throw new DSSException("More than one result for XPath: " + xPathQuery);
        }
        return list.item(0);
    }

    /**
     * Returns the Element corresponding to the XPath query.
     *
     * @param xmlNode
     *            The node where the search should be performed.
     * @param xPathQuery
     *            {@link XPathQuery}
     * @return the Element corresponding to the XPath query
     */
    public static Element getElement(final Node xmlNode, final XPathQuery xPathQuery) {
        return (Element) getNode(xmlNode, xPathQuery);
    }

    /**
     * Returns an amount of found nodes matching the {@code xPathString}
     *
     * @param xmlNode
     *            the current node
     * @param xPathQuery
     *            {@link XPathQuery}
     * @return an amount of returned nodes
     */
    public static int getNodesAmount(final Node xmlNode, final XPathQuery xPathQuery) {
        final NodeList list = getNodeList(xmlNode, xPathQuery);
        return list.getLength();
    }

    /**
     * This method returns the list of children's names for a given {@code Node}.
     *
     * @param xmlNode
     *            The node where the search should be performed.
     * @param xPathQuery
     *            {@link XPathQuery}
     * @return {@code List} of children's names
     */
    public static List<String> getChildrenNames(final Node xmlNode, final XPathQuery xPathQuery) {
        List<String> childrenNames = new ArrayList<>();
        final Element element = getElement(xmlNode, xPathQuery);
        if (element != null) {
            final NodeList unsignedProperties = element.getChildNodes();
            for (int ii = 0; ii < unsignedProperties.getLength(); ++ii) {
                final Node node = unsignedProperties.item(ii);
                if (node.getLocalName() != null) {
                    childrenNames.add(node.getLocalName());
                }
            }
        }
        return childrenNames;
    }

    /**
     * Extract an element from the given document {@code node} with the given Id.
     * The method is namespace independent.
     *
     * @param node {@link Node} containing the element with the Id
     * @param id {@link String} id of an element to find
     * @return {@link Element} with the given Id, NULL if unique result is not found
     */
    public static Element getElementById(Node node, String id) {
        return getElementById(node, XPathQueryBuilder.allFromCurrentPosition().build(), id);
    }

    /**
     * Extract an element from the given {@code node} according to the {@code xPathQuery}
     * with the matching {@code id} if any.
     * This method normalizes id safely (ensuring it is not a URI or XPointer value).
     *
     * @param node {@link Node} containing the element with the Id
     * @param xPathQuery {@link XPathQuery}
     * @param id {@link String} id of an element to find
     * @return {@link Element} with the given Id, NULL if unique result is not found
     */
    public static Element getElementById(Node node, XPathQuery xPathQuery, String id) {
        try {
            return getElement(node, XPathQueryBuilder.fromXPathQuery(xPathQuery).idValue(DomUtils.getId(id)).build());
        } catch (Exception e) {
            String errorMessage = "An exception occurred during an attempt to extract an element with XPath query '{}' by its Id '{}' : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, xPathQuery, id, e.getMessage(), e);
            } else {
                LOG.warn(errorMessage, xPathQuery, id, e.getMessage());
            }
            return null;
        }
    }

}
