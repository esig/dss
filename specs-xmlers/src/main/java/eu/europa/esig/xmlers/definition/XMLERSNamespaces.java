package eu.europa.esig.xmlers.definition;

import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;

/**
 * Defines a list of used XMLERS namespaces
 */
public class XMLERSNamespaces {

    /** The XMLERS namespace */
    public static final DSSNamespace XMLERS = new DSSNamespace("urn:ietf:params:xml:ns:ers", "ers");

    /**
     * Empty constructor
     */
    private XMLERSNamespaces() {
        // empty
    }

}
