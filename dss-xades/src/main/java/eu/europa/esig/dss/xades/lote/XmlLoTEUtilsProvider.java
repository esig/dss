package eu.europa.esig.dss.xades.lote;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.lote.xml.LOTEUtils;

/**
 * This class provides an instance of {@code eu.europa.esig.lote.xml.LOTEUtils}.
 * NOTE: "specs-lote-xml" represents an optional module, therefore we use a proxy class.
 *
 */
public class XmlLoTEUtilsProvider {

    /**
     * Default constructor
     */
    private XmlLoTEUtilsProvider() {
        // empty
    }

    /**
     * Gets utils for a TS 119 612 v2.4.1 XML Trusted List
     *
     * @return {@link XSDAbstractUtils}
     */
    public static XSDAbstractUtils getUtils() {
        return LOTEUtils.getInstance();
    }

}
