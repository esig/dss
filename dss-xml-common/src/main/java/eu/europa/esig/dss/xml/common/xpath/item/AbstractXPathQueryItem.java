package eu.europa.esig.dss.xml.common.xpath.item;

import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Contains common implementation of the XPath expression item.
 *
 */
public abstract class AbstractXPathQueryItem implements XPathQueryItem {

    /** Next XPath expression item to be executed */
    private XPathQueryItem nextItem;

    /** List of applicable parameters */
    private List<XPathQueryParameter> parameters;

    /**
     * Default constructor
     */
    protected AbstractXPathQueryItem() {
        // empty
    }

    @Override
    public XPathQueryItem nextItem() {
        return nextItem;
    }

    @Override
    public XPathQueryItem setNextItem(XPathQueryItem nextItem) {
        this.nextItem = nextItem;
        return nextItem;
    }

    @Override
    public boolean matchNode(Node node) {
        if (!process(node)) {
            return false;
        }
        if (parameters != null && !parameters.isEmpty()) {
            for (XPathQueryParameter parameter : parameters) {
                if (!parameter.matchNode(node)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * This method executes the XPath query item requirement, and returns whether the {@code node} satisfies the rule
     *
     * @param node {@link Node} to verify
     * @return TRUE if the condition matches, FALSE otherwise
     */
    protected abstract boolean process(Node node);

    @Override
    public void addParameter(XPathQueryParameter parameter) {
        if (parameters == null) {
            parameters = new ArrayList<>();
        }
        parameters.add(parameter);
    }

    @Override
    public List<XPathQueryParameter> getParameters() {
        if (parameters == null) {
            return Collections.emptyList();
        }
        return parameters;
    }

    @Override
    public boolean isEmpty() {
        return false;
    }

    /**
     * Gets the local name of a Node, without prefix, if any
     *
     * @param node {@link Node}
     * @return {@link String}
     */
    protected String getLocalName(Node node) {
        return node.getLocalName() != null ? node.getLocalName() : node.getNodeName();
    }

    @Override
    public String toString() {
        return String.format("%s : %s", getClass().getSimpleName(), getQueryString());
    }

}
