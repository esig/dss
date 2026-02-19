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
package eu.europa.esig.lote.json;

import eu.europa.esig.json.JSONSchemaAbstractUtils;

import java.net.URI;
import java.util.Map;

/**
 * This class contains utils for parsing and validation of the list of Trusted Entities to
 * the ETSI TS 119 602 JSON schema
 *
 */
public final class LOTEJsonUtils extends JSONSchemaAbstractUtils {

    /** LoTE schema URI */
    private static final String SCHEMA_URI =  "1960201_json_schema.json";

    /** LoTE SIE extension schema URI */
    private static final String SIE_SCHEMA_URI =  "1960201_json_schema_sie.json";

    /** LoTE Additional Types extension schema URI */
    private static final String ADDITIONAL_TYPES_SCHEMA_URI =  "1960201_json_schema_tie.json";

    /** RFC 7517 schema URI */
    private static final String RFC7517_URI = "rfcs/rfc7517.json";

    /** LoTE schema's location */
    private static final String SCHEMA_LOCATION = "/schema/1960201_json_schema.json";

    /** LoTE SIE Extension schema's location */
    private static final String SIE_EXTENSION_SCHEMA_LOCATION = "/schema/1960201_json_schema_sie.json";

    /** LoTE Additional Types Extension schema's location */
    private static final String ADDITIONAL_TYPES_SCHEMA_LOCATION = "/schema/1960201_json_schema_tie.json";

    /** RFC 7517 schema's location */
    private static final String RFC7517_SCHEMA_LOCATION = "/schema/rfcs/rfc7517.json";

    /** Singleton instance */
    private static LOTEJsonUtils singleton;

    /**
     * Empty constructor
     */
    private LOTEJsonUtils() {
        // empty
    }

    /**
     * Returns instance of {@code LOTEJsonUtils}
     *
     * @return {@link LOTEJsonUtils}
     */
    public static LOTEJsonUtils getInstance() {
        if (singleton == null) {
            singleton = new LOTEJsonUtils();
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
        definitions.put(URI.create(RFC7517_URI), RFC7517_SCHEMA_LOCATION);
        definitions.put(URI.create(SCHEMA_URI), SCHEMA_LOCATION);
        definitions.put(URI.create(SIE_SCHEMA_URI), SIE_EXTENSION_SCHEMA_LOCATION);
        definitions.put(URI.create(ADDITIONAL_TYPES_SCHEMA_URI), ADDITIONAL_TYPES_SCHEMA_LOCATION);
        return definitions;
    }

}
