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
package eu.europa.esig.dss.enumerations;

import java.util.Objects;

/**
 * Defines a TSLType element of a Trusted List
 *
 */
public interface TSLType extends UriBasedEnum {

    /**
     * Gets label
     *
     * @return {@link String}
     */
    String getLabel();

    /**
     * This method returns a {@code TSLType} for the given URI
     *
     * @param uri {@link String}
     * @return {@link TSLTypeEnum}
     */
    static TSLType fromUri(String uri) {
        Objects.requireNonNull(uri, "URI cannot be null!");

        for (TSLType type : TSLTypeEnum.values()) {
            if (type.getUri().equals(uri)) {
                return type;
            }
        }
        return new TSLType() {

            private static final long serialVersionUID = -2240326302871808895L;

            @Override
            public String getUri() { return uri; }
            @Override
            public String getLabel() { return null; }
        };
    }

}
