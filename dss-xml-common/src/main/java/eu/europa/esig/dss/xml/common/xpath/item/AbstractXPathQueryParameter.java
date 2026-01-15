package eu.europa.esig.dss.xml.common.xpath.item;

import org.w3c.dom.Node;

import java.util.Collections;
import java.util.List;

/**
 * Abstract implementation of a XPathQueryParameter containing common methods and logic
 *
 */
public abstract class AbstractXPathQueryParameter extends AbstractXPathQueryItem implements XPathQueryParameter {

    /**
     * Default constructor
     */
    protected AbstractXPathQueryParameter() {
        super();
    }

    @Override
    public void addParameter(XPathQueryParameter parameter) {
        throw new UnsupportedOperationException("Unable to set a parameter for XPathQueryParameter!");
    }

    @Override
    public List<XPathQueryParameter> getParameters() {
        // not supported
        return Collections.emptyList();
    }

    @Override
    public boolean matchNode(Node node) {
        return process(node);
    }

}
