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
 * Contains utils for JAdES Protected header validation against JSON schemas
 *
 */
public class JAdESProtectedHeaderUtils extends AbstractJAdESUtils {

    /** The protected header schema URI for a JAdES signature */
    private static final String JAdES_PROTECTED_HEADER_SCHEMA_URI = "19182-protected-jsonSchema.json";

    /** The protected header schema for a JAdES signature */
    private static final String JAdES_PROTECTED_HEADER_SCHEMA_LOCATION = "/schema/19182-protected-jsonSchema.json";

    /** Singleton instance */
    private static JAdESProtectedHeaderUtils singleton;

    /**
     * Empty constructor
     */
    private JAdESProtectedHeaderUtils() {
        // empty
    }

    /**
     * Returns instance of {@code JAdESProtectedHeaderUtils}
     *
     * @return {@link JAdESProtectedHeaderUtils}
     */
    public static JAdESProtectedHeaderUtils getInstance() {
        if (singleton == null) {
            singleton = new JAdESProtectedHeaderUtils();
        }
        return singleton;
    }

    @Override
    public String getSchemaURI() {
        return JAdES_PROTECTED_HEADER_SCHEMA_URI;
    }

    @Override
    public Map<URI, String> getSchemaDefinitions() {
        Map<URI, String> definitions = super.getSchemaDefinitions();
        definitions.put(URI.create(JAdES_PROTECTED_HEADER_SCHEMA_URI), JAdES_PROTECTED_HEADER_SCHEMA_LOCATION);
        return definitions;
    }

}
