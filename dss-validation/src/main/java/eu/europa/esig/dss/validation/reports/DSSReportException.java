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
package eu.europa.esig.dss.validation.reports;

/**
 * Exception to be thrown in case of JAXB Report marshaling or unmarshaling error
 */
public class DSSReportException extends RuntimeException {

	private static final long serialVersionUID = -2849739549071583052L;

    /**
     * Empty constructor
     */
	public DSSReportException() {
        super();
    }

    /**
     * Constructor with an exception message
     *
     * @param message {@link String}
     */
    public DSSReportException(String message) {
        super(message);
    }

    /**
     * Constructor with a caused exception or error
     *
     * @param cause {@link Throwable}
     */
    public DSSReportException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructor with a caused exception or error and a custom message
     *
     * @param cause {@link Throwable}
     * @param message {@link String}
     */
    public DSSReportException(String message, Throwable cause) {
        super(message, cause);
    }

}
