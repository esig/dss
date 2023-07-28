package eu.europa.esig.dss.evidencerecord.xml.definition;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.DSSNamespace;

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

    /**
     * Registers the namespaces
     */
    public static void registerNamespaces() {
        DomUtils.registerNamespace(XMLERS);
    }

}
