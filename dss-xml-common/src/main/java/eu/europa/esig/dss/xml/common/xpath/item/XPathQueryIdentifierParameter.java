package eu.europa.esig.dss.xml.common.xpath.item;

import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;

/**
 * Builds an XPath expression part for an element retrieval by any identifier type
 * (suitable types are: 'Id', 'ID', 'id').
 */
public class XPathQueryIdentifierParameter extends XPathQueryAttributeParameter {

    /**
     * Default constructor
     */
    public XPathQueryIdentifierParameter(final String idValue) {
        super(XMLDSigAttribute.ID, idValue, true);
    }

    /**
     * Gets the ID String value
     *
     * @return {@link String} ID
     */
    public String getId() {
        return getAttributeValue();
    }

}
