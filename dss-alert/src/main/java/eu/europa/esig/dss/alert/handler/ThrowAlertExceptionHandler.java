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
package eu.europa.esig.dss.alert.handler;

import eu.europa.esig.dss.alert.exception.AlertException;

/**
 * Handler which throws an {@code AlertException}
 * 
 * @param <T> class of an object to process
 */
public class ThrowAlertExceptionHandler<T> implements AlertHandler<T> {

	/**
	 * Default constructor
	 */
	public ThrowAlertExceptionHandler() {
		// empty
	}

	@Override
	public void process(T object) {
		throw new AlertException(object.toString());
	}

}
