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
package eu.europa.esig.dss.pades.exception;

import eu.europa.esig.dss.model.DSSException;

/**
 * Thrown when the document is protected (the requested operation is not permitted)
 *
 */
public class ProtectedDocumentException extends DSSException {

	private static final long serialVersionUID = 7616019266734940111L;

	/**
	 * Default constructor with a message
	 *
	 * @param message {@link String}
	 */
	public ProtectedDocumentException(String message) {
		super(message);
	}
	
}
