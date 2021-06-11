package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;

import java.util.List;

/**
 * Wrapper for a list of {@code eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName}s
 *
 */
public class DistinguishedNameListWrapper {

    /** The distinguished names */
    private final List<XmlDistinguishedName> xmlDistinguishedNames;

    /**
     * Default constructor
     *
     * @param xmlDistinguishedNames a list of {@link XmlDistinguishedName}s
     */
    public DistinguishedNameListWrapper(final List<XmlDistinguishedName> xmlDistinguishedNames) {
        this.xmlDistinguishedNames = xmlDistinguishedNames;
    }

    /**
     * Returns a value according to the given {@code format}
     *
     * @param format {@link String} to get distinguished name value
     * @return {@link String}
     */
    public String getValue(String format) {
        if (xmlDistinguishedNames != null) {
            for (XmlDistinguishedName distinguishedName : xmlDistinguishedNames) {
                if (distinguishedName.getFormat().equals(format)) {
                    return distinguishedName.getValue();
                }
            }
        }
        return "";
    }

}
