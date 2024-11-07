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
package eu.europa.esig.dss.spi.exception;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;

/**
 * The exception to be thrown in case of an external error arisen during a data loader requests
 *
 */
public class DSSExternalResourceException extends DSSException {

	private static final long serialVersionUID = 8290929546359871166L;

    /**
     * Empty constructor
     */
	DSSExternalResourceException() {
		super();
	}

    /**
     * Constructor with a message
     *
     * @param message {@link String}
     */
    public DSSExternalResourceException(String message) {
        super(message);
    }

    /**
     * Re-throwable constructor
     *
     * @param cause {@link Throwable}
     */
    public DSSExternalResourceException(Throwable cause) {
        super(cause);
    }

    /**
     * Re-throwable constructor with a custom message
     *
     * @param message {@link String}
     * @param cause {@link Throwable}
     */
    public DSSExternalResourceException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Returns cause {@code String} message
     * 
     * @return {@link String} caused exception's message
     */
    String getCauseMessage() {
        Throwable cause = getCause();
        if (cause != null) {
            return cause.getMessage();
        }
        return Utils.EMPTY_STRING;
    }

}
