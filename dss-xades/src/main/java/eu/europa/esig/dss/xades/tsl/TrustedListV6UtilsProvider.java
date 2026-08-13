package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.trustedlist.TrustedListUtils;

/**
 * This class provides an instance of {@code eu.europa.esig.trustedlist.TrustedListUtils}.
 * NOTE: "specs-trusted-list" represents an optional module, therefore we use a proxy class.
 *
 */
public class TrustedListV6UtilsProvider {

    /**
     * Default constructor
     */
    private TrustedListV6UtilsProvider() {
        // empty
    }

    /**
     * Gets utils for a TS 119 612 v2.4.1 XML Trusted List
     *
     * @return {@link XSDAbstractUtils}
     */
    public static XSDAbstractUtils getUtils() {
        return TrustedListUtils.getInstance();
    }

}
