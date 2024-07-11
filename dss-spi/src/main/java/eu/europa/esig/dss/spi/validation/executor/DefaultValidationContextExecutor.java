/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.validation.executor;

import eu.europa.esig.dss.spi.validation.ValidationContext;

import java.util.Objects;

/**
 * This class performs basic validation of {@code eu.europa.esig.dss.spi.validation.ValidationContext},
 * including certificate chain building and revocation data extraction, without executing different validity checks
 *
 */
public class DefaultValidationContextExecutor implements ValidationContextExecutor {

    /** Singleton instance */
    public static final DefaultValidationContextExecutor INSTANCE = new DefaultValidationContextExecutor();

    /**
     * Default constructor
     */
    private DefaultValidationContextExecutor() {
        // empty
    }

    @Override
    public void validate(ValidationContext validationContext) {
        Objects.requireNonNull(validationContext, "ValidationContext cannot be null!");
        validationContext.validate();
    }

}
