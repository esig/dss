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
package eu.europa.esig.dss.spi.client.http;

import java.io.Serializable;
import java.util.List;

/**
 * Component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
 *
 */
public interface DataLoader extends Serializable {

	/**
	 * This is an internal class used to model the couple data and url used to obtain this data.
	 */
	class DataAndUrl {

		/**
		 * Url used to obtain data.
		 */
		private final String urlString;

		/**
		 * Obtained data.
		 */
		private final byte[] data;

		/**
		 * Default constructor
		 *
		 * @param urlString {@link String} url
		 * @param data a byte array
		 */
		public DataAndUrl(final String urlString, final byte[] data) {
			this.urlString = urlString;
			this.data = data;
		}
		
		/**
		 * Gets the URL string used to download the data
		 *
		 * @return {@link String}
		 */
		public String getUrlString() {
			return urlString;
		}
		
		/**
		 * Gets the downloaded data
		 *
		 * @return a byte array
		 */
		public byte[] getData() {
			return data;
		}
		
	}

	/**
	 * Execute a HTTP GET operation.
	 *
	 * @param url
	 *            the url to access
	 * @return {@code byte} array of obtained data or null
	 */
	byte[] get(final String url);

	/**
	 * Execute a HTTP GET operation. This method is used when many URls are available to access the same resource. The
	 * operation stops after the first successful download.
	 *
	 * @param urlStrings
	 *            {@code List} of {@code String}s representing the URLs to be used in sequential way to obtain the data.
	 * @return {@code DataAndUrl} representing the array of obtained data and used url, or null
	 */
	DataAndUrl get(final List<String> urlStrings);

	/**
	 * Executes a HTTP POST operation
	 *
	 * @param url
	 *            to access
	 * @param content
	 *            the content to post
	 * @return {@code byte} array of obtained data
	 */
	byte[] post(final String url, final byte[] content);

	/**
	 * This allows to set the content type. Example: Content-Type "application/ocsp-request"
	 *
	 * @param contentType
	 *            to set the Content-Type
	 */
	void setContentType(final String contentType);

}
