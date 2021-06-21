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
package eu.europa.esig.dss.spi.exception;

import eu.europa.esig.dss.model.DSSException;

/**
 * The exception to be thrown in case of an external error arisen during a data loader requests
 *
 */
public class DSSExternalResourceException extends DSSException {

	private static final long serialVersionUID = 8290929546359871166L;
	
	DSSExternalResourceException() {
		super();
	}

    public DSSExternalResourceException(String message) {
        super(message);
    }

    public DSSExternalResourceException(Throwable cause) {
        super(cause);
    }

    public DSSExternalResourceException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Returns cause {@code String} message
     * @return {@link String} caused exception's message
     */
    String getCauseMessage() {
    	return getCause().getMessage();
    }

}
