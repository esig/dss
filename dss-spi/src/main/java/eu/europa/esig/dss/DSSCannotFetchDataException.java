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
package eu.europa.esig.dss;

import java.io.IOException;
import java.net.UnknownHostException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

/**
 * Exception when the data cannot be fetched
 *
 *
 */
public class DSSCannotFetchDataException extends RuntimeException {

	private static final long serialVersionUID = -1112490792269827445L;

	private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/esig/dss/i18n");

	private MSG key;

	private Exception cause;

	private String serviceName;

	/**
	 * Supported messages
	 */
	public enum MSG {
		IO_EXCEPTION, TIMOUT_EXCEPTION, SIZE_LIMIT_EXCEPTION, UNKNOWN_HOST_EXCEPTION, RESOURCE_NOT_FOUND_EXCEPTION
	}

	/**
	 * The default constructor for DSSCannotFetchDataException.
	 *
	 * @param message
	 */
	public DSSCannotFetchDataException(MSG message, String serviceName) {
		if (message == null) {
			throw new IllegalArgumentException("Cannot build Exception without a message");
		}
		this.key = message;
		this.serviceName = serviceName;
	}

	/**
	 * The default constructor for DSSCannotFetchDataException.
	 *
	 * @param ex
	 */
	public DSSCannotFetchDataException(IOException ex, String serviceName) {
		this(ex instanceof UnknownHostException ? MSG.UNKNOWN_HOST_EXCEPTION : MSG.IO_EXCEPTION, serviceName);
		cause = ex;
		this.serviceName = serviceName;
	}

	@Override
	public String getLocalizedMessage() {
		MessageFormat format = new MessageFormat(bundle.getString(key.toString()));
		Object[] args = new Object[]{serviceName};
		return format.format(args) + (cause == null ? "" : (" --> " + cause.getMessage()));
	}

}
