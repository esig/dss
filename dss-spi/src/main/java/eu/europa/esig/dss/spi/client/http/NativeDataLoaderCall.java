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

	/** Timeout on opening a connection with remote resource */
	private final int connectTimeout;

	/** Timeout on reading a response from remote resource */
	private final int readTimeout;

	/**
	 * Constructor with unconfigured timeout
	 *
	 * @param url {@link String}
	 * @param content byte array
	 * @param useCaches if the caches shall be used
	 * @param maxInputSize maximum InputStream size
	 */
	public NativeDataLoaderCall(String url, byte[] content, boolean useCaches, int maxInputSize) {
		this(url, content, useCaches, maxInputSize, 0, 0);
	}

	/**
	 * Constructor with configured timeouts
	 *
	 * @param url {@link String}
	 * @param content byte array
	 * @param useCaches if the caches shall be used
	 * @param maxInputSize maximum InputStream size
	 * @param connectTimeout timeout on opening a connection (in milliseconds)
	 * @param readTimeout timeout on reading a response from a remote resource (in milliseconds)
	 */
	public NativeDataLoaderCall(String url, byte[] content, boolean useCaches, int maxInputSize,
								int connectTimeout, int readTimeout) {
		this.url = url;
		this.content = content;
		this.useCaches = useCaches;
		this.maxInputSize = maxInputSize;
		this.connectTimeout = connectTimeout;
		this.readTimeout = readTimeout;
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
			if (connectTimeout > 0) {
				connection.setConnectTimeout(connectTimeout);
			}
			if (readTimeout > 0) {
				connection.setReadTimeout(readTimeout);
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

}
