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

import java.net.URI;
import java.util.Map;

/**
 * Contains utils for JAdES Unprotected header validation against JSON schemas
 *
 */
public class JAdESUnprotectedHeaderUtils extends AbstractJAdESUtils {

    /** The unprotected header schema URI for a JAdES signature */
    private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_URI = "19182-unprotected-jsonSchema.json";

    /** The unprotected header schema for a JAdES signature */
    private static final String JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION = "/schema/19182-unprotected-jsonSchema.json";

    /** Singleton instance */
    private static JAdESUnprotectedHeaderUtils singleton;

    /**
     * Empty constructor
     */
    private JAdESUnprotectedHeaderUtils() {
        // empty
    }

    /**
     * Returns instance of {@code JAdESUnprotectedHeaderUtils}
     *
     * @return {@link JAdESUnprotectedHeaderUtils}
     */
    public static JAdESUnprotectedHeaderUtils getInstance() {
        if (singleton == null) {
            singleton = new JAdESUnprotectedHeaderUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return JAdES_UNPROTECTED_HEADER_SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = super.getSchemaDefinitions();
        definitions.put(URI.create(JAdES_UNPROTECTED_HEADER_SCHEMA_URI), JAdES_UNPROTECTED_HEADER_SCHEMA_LOCATION);
        return definitions;
    }

}
