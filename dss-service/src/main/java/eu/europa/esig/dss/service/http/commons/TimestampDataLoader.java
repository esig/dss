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
package eu.europa.esig.dss.service.http.commons;

/**
 * Implementation of DataLoader using HttpClient to request a timestamp server.
 */
public class TimestampDataLoader extends CommonsDataLoader {

	private static final String TIMESTAMP_QUERY_CONTENT_TYPE = "application/timestamp-query";

	/**
	 * The default constructor for CommonsDataLoader.
	 */
	public TimestampDataLoader() {
		super(TIMESTAMP_QUERY_CONTENT_TYPE);
	}

	/**
	 * In case of TimestampDataLoader the contentType is fixed to: Content-Type "application/timestamp-query"
	 *
	 * @param contentType {@link String}
	 */
	@Override
	public void setContentType(final String contentType) {
		throw new UnsupportedOperationException("Content type change is not supported by this implementation!");
	}

}
