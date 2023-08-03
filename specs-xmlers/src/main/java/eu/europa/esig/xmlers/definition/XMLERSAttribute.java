package eu.europa.esig.xmlers.definition;

import eu.europa.esig.dss.jaxb.common.definition.DSSAttribute;

/**
 * Represents a collection of attributes defined in XMLERS XSD schema
 *
 */
public enum XMLERSAttribute implements DSSAttribute {

    /** Version */
    VERSION("Version"),

    /** Order */
    ORDER("Order"),

    /** Algorithm */
    ALGORITHM("Algorithm"),

    /** Type */
    TYPE("Type");

    /** Attribute name */
    private final String attributeName;

    /**
     * Default constructor
     *
     * @param attributeName {@link String}
     */
    XMLERSAttribute(String attributeName) {
        this.attributeName = attributeName;
    }

    @Override
    public String getAttributeName() {
        return attributeName;
    }

}
