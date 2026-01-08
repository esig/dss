package eu.europa.esig.dss.xml.common.xpath.item;

import eu.europa.esig.dss.xml.common.definition.DSSAttribute;
import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Builds an XPath expression part for an element retrieval by any identifier type
 * (suitable types are: 'Id', 'ID', 'id').
 */
public class XPathQueryIdentifierParameter extends AbstractXPathQueryParameter {

    /** Array of possible Id attribute local names */
    private static final String[] ID_ATTRIBUTES = { "Id", "id", "ID"  };

    /** Value of the Id attribute to look for */
    private final String idValue;

    /** Cached list of parameters to be used for processing of the query */
    private final List<XPathQueryAttributeParameter> attributeParameters;

    /**
     * Default constructor
     */
    public XPathQueryIdentifierParameter(final String idValue) {
        Objects.requireNonNull(idValue, "ID Value cannot be null!");
        this.idValue = idValue;
        this.attributeParameters = initAttributeParameters(idValue);
    }

    private static List<XPathQueryAttributeParameter> initAttributeParameters(final String idValue) {
        List<XPathQueryAttributeParameter> parameters = new ArrayList<>();
        Arrays.stream(ID_ATTRIBUTES).forEach(a -> parameters.add(new XPathQueryAttributeParameter(DSSAttribute.fromDefinition(a), idValue)));
        return parameters;
    }

    /**
     * Gets the ID String value
     *
     * @return {@link String} ID
     */
    public String getId() {
        return idValue;
    }

    @Override
    protected boolean process(Node node) {
        for (XPathQueryParameter parameter : attributeParameters) {
            if (parameter.matchNode(node)) {
                return true;
            }
        }
        return false;
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
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < attributeParameters.size(); i++) {
            XPathQueryParameter parameter = attributeParameters.get(i);
            sb.append(parameter.getQueryString());
            if (i + 1 < ID_ATTRIBUTES.length) {
                sb.append(" or ");
            }
        }
        return sb.toString();
    }

}
