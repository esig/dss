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

import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.Callable;

/**
 * The call of native java DataLoader using the java.net.URL class.
 *
 */
public class NativeDataLoaderCall implements Callable<byte[]> {

	/** The default error message */
	private static final String ERROR_MESSAGE = "An error occurred while reading from url '%s' : %s";

	/** The URL */
	private final String url;

	/** The content */
	private final byte[] content;

	/** Defines the cache is used */
	private final boolean useCaches;

	/** Max input size */
	private final int maxInputSize;

	private final int timeout;

	/**
	 * Default constructor
	 *
	 * @param url {@link String}
	 * @param content byte array
	 * @param useCaches if the caches shall be used
	 * @param maxInputSize maximum InputStream size
	 * @param timeout to the connection if required (0 for no timeout)
	 */
	public NativeDataLoaderCall(String url, byte[] content, boolean useCaches, int maxInputSize, int timeout) {
		this.url = url;
		this.content = content;
		this.useCaches = useCaches;
		this.maxInputSize = maxInputSize;
		this.timeout = timeout;
	}
	
	@Override
	public byte[] call() {
		OutputStream os = null;
		InputStream is = null;
		byte[] result;
		try {
			URLConnection connection = createConnection();
			connection.setUseCaches(useCaches);
			connection.setDoInput(true);
			if (timeout > 0) {
				connection.setConnectTimeout(timeout);
				connection.setReadTimeout(timeout);
			}
			if (content != null) {
				connection.setDoOutput(true);
				os = connection.getOutputStream();
				Utils.write(content, os);
			}
			is = connection.getInputStream();
			if (maxInputSize > 0) {
				is = new MaxSizeInputStream(is, maxInputSize, url);
			}
			result = Utils.toByteArray(is);

		} catch (IOException e) {
			throw new DSSExternalResourceException(String.format(ERROR_MESSAGE, url, e.getMessage()), e);
		} finally {
			Utils.closeQuietly(os);
			Utils.closeQuietly(is);
		}
		return result;
	}

	/**
	 * Creates connection
	 *
	 * @return {@link URLConnection}
	 * @throws IOException if IOException occurred
	 */
	protected URLConnection createConnection() throws IOException {
		return new URL(url).openConnection();
	}

	/**
	 * Gets URL
	 *
	 * @return {@link String}
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * Gets content
	 *
	 * @return byte array
	 */
	public byte[] getContent() {
		return content;
	}

	/**
	 * Gets the maximum InputStream size
	 *
	 * @return maximum InputStream size
	 */
	public long getMaxInputSize() {
		return maxInputSize;
	}

	/**
	 * Gets if the caches are used
	 *
	 * @return TRUE if to use caches, FALSE otherwise
	 */
	public boolean isUseCaches() {
		return useCaches;
	}

}
