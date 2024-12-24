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

/**
 * Defines possible levels for messages returned by the validation process
 *
 */
public enum MessageType implements UriBasedEnum {

    /**
     * The message indicates a reason for validation process failure
     */
    ERROR("urn:cef:dss:message:error"),

    /**
     * The message indicates a reason for an issue occurred during the validation, not blocking the process
     */
    WARN("urn:cef:dss:message:warning"),

    /**
     * The additional informational message returned by the validation process
     */
    INFO("urn:cef:dss:message:information");

    /** VR URI of the constraint */
    private final String uri;

    /**
     * Default constructor
     *
     * @param uri {@link String}
     */
    MessageType(String uri) {
        this.uri = uri;
    }

    @Override
    public String getUri() {
        return uri;
    }

}
