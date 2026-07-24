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
package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.jades.DSSJsonUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Default implementation of an {@code SDJWTDisclosureBuilder}.
 * Creates a base64url disclosure String for a given claim, e.g. for a disclosure:
 * {@code ["_26bc4LT-ac6q2KI6cBW5es","family_name","Möbius"]}
 * The returned base64url encoded String is:
 * {@code WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0}
 *
 */
public class DefaultSDJWTSelectiveDisclosureBuilder implements SDJWTSelectiveDisclosureBuilder {

    /**
     * Default constructor
     *
     */
    public DefaultSDJWTSelectiveDisclosureBuilder() {
        // empty
    }

    @Override
    public SDJWTSelectiveDisclosure build(String name, Object value, String salt) {
        Objects.requireNonNull(value, "Value cannot be null!");
        Objects.requireNonNull(salt, "Salt cannot be null!");
        List<Object> data = new ArrayList<>();
        data.add(salt);
        if (name != null) {
            data.add(name);
        }
        data.add(value);
        return new SDJWTSelectiveDisclosure(DSSJsonUtils.toBase64Url(data));
    }

}
