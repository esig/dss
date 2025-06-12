/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.policy.crypto.json;

import eu.europa.esig.json.JSONSchemaAbstractUtils;

import java.net.URI;
import java.util.Map;

/**
 * This class contains utils for parsing and validation of the cryptographic suites according to
 * the ETSI TS 119 322 JSON schema
 *
 */
public final class CryptographicSuiteJsonUtils extends JSONSchemaAbstractUtils {

    /** Cryptographic suite schema URI */
    private static final String SCHEMA_URI = "http://uri.etsi.org/19322/algoCatSchema";

    /** Cryptographic suite schema's location */
    private static final String SCHEMA_LOCATION = "/schema/19322algocatjsonschema.json";

    /** Singleton instance */
    private static CryptographicSuiteJsonUtils singleton;

    /**
     * Empty constructor
     */
    private CryptographicSuiteJsonUtils() {
        // empty
    }

    /**
     * Returns instance of {@code CryptographicSuiteJsonUtils}
     *
     * @return {@link CryptographicSuiteJsonUtils}
     */
    public static CryptographicSuiteJsonUtils getInstance() {
        if (singleton == null) {
            singleton = new CryptographicSuiteJsonUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = getJSONSchemaDefinitions();
        definitions.put(URI.create(SCHEMA_URI), SCHEMA_LOCATION);
        return definitions;
    }

}
