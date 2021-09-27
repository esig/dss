package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.Context;

/**
 * Parses {@code CertificationPermission}
 *
 */
public class CertificationPermissionParser {

    /**
     * Default constructor
     */
    private CertificationPermissionParser() {
    }

    /**
     * Parses the value and returns {@code CertificationPermission}
     *
     * @param v {@link String} to parse
     * @return {@link CertificationPermission}
     */
    public static CertificationPermission parse(String v) {
        if (v != null) {
            return CertificationPermission.valueOf(v);
        }
        return null;
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link Context}
     * @return {@link String}
     */
    public static String print(CertificationPermission v) {
        if (v != null) {
            return v.name();
        }
        return null;
    }

}
