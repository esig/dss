package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.trustedlist211.TrustedList211Utils;

/**
 * This class provides an instance of {@code eu.europa.esig.trustedlist211.TrustedList211Utils}.
 * NOTE: "specs-trusted-list-v211" represents an optional module, therefore we use a proxy class.
 *
 */
public class TrustedListV5UtilsProvider {

    /**
     * Default constructor
     */
    private TrustedListV5UtilsProvider() {
        // empty
    }

    /**
     * Gets utils for a TS 119 612 v2.1.1 XML Trusted List
     *
     * @return {@link XSDAbstractUtils}
     */
    public static XSDAbstractUtils getUtils() {
        return TrustedList211Utils.getInstance();
    }

}
