package eu.europa.esig.trustedlist.definition;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

/**
 * This class contains constants for Trusted List XSD and its namespace.
 *
 */
public class TrustedListNamespace {

    /** Namespace URI */
    public static final DSSNamespace NS = new DSSNamespace("http://uri.etsi.org/02231/v2#", "tl");

    /**
     * Utils class
     */
    private TrustedListNamespace() {
        // empty
    }

}
