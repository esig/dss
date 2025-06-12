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
package eu.europa.esig.jades;

import eu.europa.esig.jws.AbstractJWSUtils;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Abstract class for JAdES signature validation against JSON schemas
 *
 */
public abstract class AbstractJAdESUtils extends AbstractJWSUtils {

    /** The RFC 7519 schema of definitions */
    protected static final String RFC7519_SCHEMA_LOCATION = "/schema/rfcs/rfc7519.json";

    /** The RFC 7519 schema name URI */
    protected static final String RFC7519_SCHEMA_URI = "rfc7519.json";

    /** The RFC 7797 schema of definitions */
    protected static final String RFC7797_SCHEMA_LOCATION = "/schema/rfcs/rfc7797.json";

    /** The RFC 7797 schema name URI */
    protected static final String RFC7797_SCHEMA_URI = "rfc7797.json";

    /** Subfolder with RFC definitions */
    protected static final String RFC_SUBDIRECTORY = "rfcs/";

    /** The JAdES schema name URI */
    protected static final String JAdES_SCHEMA_DEFINITIONS_URI = "19182-jsonSchema.json";

    /** The JAdES schema of definitions */
    protected static final String JAdES_SCHEMA_DEFINITIONS_LOCATION = "/schema/19182-jsonSchema.json";

    /**
     * Default constructor
     */
    protected AbstractJAdESUtils() {
        // empty
    }

    @Override
    public Map<URI, String> getRFCDefinitions() {
        final Map<URI, String> definitions = new HashMap<>();
        Map<URI, String> rfcDefinitions = super.getRFCDefinitions();
        for (Map.Entry<URI, String> entry : rfcDefinitions.entrySet()) {
            definitions.put(URI.create(RFC_SUBDIRECTORY + entry.getKey().toString()), entry.getValue());
        }
        definitions.put(URI.create(RFC_SUBDIRECTORY + RFC7519_SCHEMA_URI), RFC7519_SCHEMA_LOCATION);
        definitions.put(URI.create(RFC_SUBDIRECTORY + RFC7797_SCHEMA_URI), RFC7797_SCHEMA_LOCATION);
        return definitions;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = getJSONSchemaDefinitions();
        definitions.putAll(getRFCDefinitions());
        definitions.put(URI.create(JAdES_SCHEMA_DEFINITIONS_URI), JAdES_SCHEMA_DEFINITIONS_LOCATION);
        return definitions;
    }

}
