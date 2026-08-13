package eu.europa.esig.dss.jades.lote;

import eu.europa.esig.json.JSONSchemaAbstractUtils;
import eu.europa.esig.lote.json.LOTEJsonUtils;

/**
 * This class provides an instance of {@code eu.europa.esig.lote.json.LOTEJsonUtils}.
 * NOTE: "specs-lote-json" represents an optional module, therefore we use a proxy class.
 *
 */
public class LOTEJsonUtilsProvider {

    /**
     * Default constructor
     */
    private LOTEJsonUtilsProvider() {
        // empty
    }

    /**
     * Gets utils for a TS 119 612 v2.4.1 JSON Trusted List
     *
     * @return {@link JSONSchemaAbstractUtils}
     */
    public static JSONSchemaAbstractUtils getUtils() {
        return LOTEJsonUtils.getInstance();
    }

}
