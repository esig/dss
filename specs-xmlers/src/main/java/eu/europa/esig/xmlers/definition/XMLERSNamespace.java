package eu.europa.esig.xmlers.definition;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

/**
 * Defines a list of used XMLERS namespaces
 */
public class XMLERSNamespace {

    /** The XMLERS namespace */
    public static final DSSNamespace XMLERS = new DSSNamespace("urn:ietf:params:xml:ns:ers", "ers");

    /**
     * Empty constructor
     */
    private XMLERSNamespace() {
        // empty
    }

}
