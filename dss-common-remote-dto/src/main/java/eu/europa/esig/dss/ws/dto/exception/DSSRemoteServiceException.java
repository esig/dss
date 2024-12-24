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
package eu.europa.esig.dss.ws.dto.exception;

/**
 * Exception to be thrown in case of Remote Service error
 */
public class DSSRemoteServiceException extends RuntimeException {

	private static final long serialVersionUID = 7836605176128624553L;

    /**
     * Empty constructor
     */
	public DSSRemoteServiceException() {
        super();
    }

    /**
     * Constructor with a message
     *
     * @param message {@link String}
     */
    public DSSRemoteServiceException(String message) {
        super(message);
    }

    /**
     * Re-throwable constructor
     *
     * @param cause {@link Throwable}
     */
    public DSSRemoteServiceException(Throwable cause) {
        super(cause);
    }

    /**
     * Re-throwable constructor with a custom message
     *
     * @param message {@link String}
     * @param cause {@link Throwable}
     */
    public DSSRemoteServiceException(String message, Throwable cause) {
        super(message, cause);
    }

}
