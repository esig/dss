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
package eu.europa.esig.dss.spi.client.http;

import eu.europa.esig.dss.model.http.ResponseEnvelope;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.Callable;

/**
 * Implementation of native java DataLoader using the java.net.URL class.
 *
 */
public class NativeHTTPDataLoader implements DataLoader, AdvancedDataLoader {

	private static final long serialVersionUID = 4075489539157157286L;

	private static final Logger LOG = LoggerFactory.getLogger(NativeHTTPDataLoader.class);

	/** Max inputStream size */
	private int maxInputSize;

	/**
	 * Timeout on the connection establishment with a remote resource.
	 */
	private int connectTimeout = 0;

	/**
	 * Timeout on the response reading from a remote resource.
	 */
	private int readTimeout = 0;

	/**
	 * Default constructor instantiating object with null values
	 */
	public NativeHTTPDataLoader() {
		// empty
	}

	@Override
	public void setContentType(String contentType) {
		throw new UnsupportedOperationException("Content type change is not supported by this implementation!");
	}

	/**
	 * Gets the maximum InputStream size
	 *
	 * @return maximum InputStream size
	 */
	public int getMaxInputSize() {
		return maxInputSize;
	}

	/**
	 * Sets the maximum InputStream size
	 *
	 * @param maxInputSize maximum InputStream size
	 */
	public void setMaxInputSize(int maxInputSize) {
		this.maxInputSize = maxInputSize;
	}

	/**
	 * Gets the timeout value on connection establishment with a remote resource
	 *
	 * @return connection timeout value
	 */
	public int getConnectTimeout() {
		return connectTimeout;
	}

	/**
	 * Sets the timeout to establish a connection with a remote resource (in milliseconds).
	 * Zero (0) value is used for no timeout.
	 * Default: 0 (no timeout)
	 *
	 * @param connectTimeout connection timeout value (in milliseconds)
	 */
	public void setConnectTimeout(int connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	/**
	 * Gets the timeout value on response reading from a remote resource
	 *
	 * @return read timeout value
	 */
	public int getReadTimeout() {
		return readTimeout;
	}

	/**
	 * Sets the timeout to read a response from a remote resource (in milliseconds).
	 * Zero (0) value is used for no timeout.
	 * Default: 0 (no timeout)
	 *
	 * @param readTimeout read timeout value (in milliseconds)
	 */
	public void setReadTimeout(int readTimeout) {
		this.readTimeout = readTimeout;
	}

	/**
	 * This method creates a task call to be executed by NativeHTTPDataLoader
	 *
	 * @param url {@link String} URL to call
	 * @param method {@link HttpMethod} of the request
	 * @param content byte array containing a body of the request, when required
	 * @param refresh defined if the cache should be used
	 * @param includeResponseDetails whether HTTP content information is to be included in the response object
	 * @param includeResponseBody whether the response message body is to be included in the output response object
	 * @return {@link Callable} task
	 */
	protected Callable<ResponseEnvelope> createNativeHTTPDataLoaderCall(String url, HttpMethod method, byte[] content,
			boolean refresh, boolean includeResponseDetails, boolean includeResponseBody) {
		NativeHTTPDataLoaderCall httpDataLoaderCall = new NativeHTTPDataLoaderCall(url, content);
		httpDataLoaderCall.setUseCaches(!refresh);
		httpDataLoaderCall.setMaxInputSize(maxInputSize);
		httpDataLoaderCall.setConnectTimeout(connectTimeout);
		httpDataLoaderCall.setReadTimeout(readTimeout);
		httpDataLoaderCall.setIncludeResponseDetails(includeResponseDetails);
		httpDataLoaderCall.setIncludeResponseBody(includeResponseBody);
		return httpDataLoaderCall;
	}

	/**
	 * Execute the request
	 *
	 * @param url {@link String}
	 * @param method {@link HttpMethod}
	 * @param content request content
	 * @param refresh if enforce the refresh
	 * @param includeResponseDetails whether HTTP content information is to be included in the response object
	 * @param includeResponseBody whether the response message body is to be included in the output response object
	 * @return response binaries
	 */
	protected ResponseEnvelope request(String url, HttpMethod method, byte[] content, boolean refresh,
									   boolean includeResponseDetails, boolean includeResponseBody) {
		try {
			Callable<ResponseEnvelope> task = createNativeHTTPDataLoaderCall(
					url, method, content, refresh, includeResponseDetails, includeResponseBody);
			return task.call();
		} catch (DSSExternalResourceException e) {
			throw e;
		} catch (Exception e) {
			throw new DSSExternalResourceException(e);
		}
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {
		for (final String urlString : urlStrings) {
			try {
				final byte[] bytes = get(urlString);
				if (bytes != null) {
					return new DataAndUrl(urlString, bytes);
				}
			} catch (Exception e) {
				LOG.warn("Impossible to obtain data using {}", urlString, e);
			}
		}
		throw new DSSExternalResourceException(String.format("No data have been obtained from urls : %s", urlStrings));
	}

	@Override
	public byte[] get(String url) {
		return get(url, false);
	}

	/**
	 * Executes a GET request to the provided URL, with a forced cache {@code refresh} when defined
	 *
	 * @param url
	 *            to access
	 * @param refresh
	 *            if true indicates that the data should be refreshed
	 * @return binaries of the extracted data object
	 */
	public byte[] get(String url, boolean refresh) {
		return request(url, HttpMethod.GET, null, refresh, false, true).getResponseBody();
	}

	@Override
	public byte[] post(String url, byte[] content) {
		return request(url, HttpMethod.POST, content, false, false, true).getResponseBody();
	}

	@Override
	public ResponseEnvelope requestGet(String url) {
		return request(url, HttpMethod.GET, null, false, true, true);
	}

	@Override
	public ResponseEnvelope requestGet(String url, boolean includeResponseDetails) {
		return request(url, HttpMethod.GET, null, false, includeResponseDetails, true);
	}

	@Override
	public ResponseEnvelope requestGet(String url, boolean includeResponseDetails, boolean includeResponseBody) {
		return request(url, HttpMethod.GET, null, false, includeResponseDetails, includeResponseBody);
	}

	@Override
	public ResponseEnvelope requestPost(String url, byte[] content) {
		return request(url, HttpMethod.POST, content, false, true, true);
	}

	@Override
	public ResponseEnvelope requestPost(String url, byte[] content, boolean includeResponseDetails) {
		return request(url, HttpMethod.POST, content, false, includeResponseDetails, true);
	}

	@Override
	public ResponseEnvelope requestPost(String url, byte[] content, boolean includeResponseDetails, boolean includeResponseBody) {
		return request(url, HttpMethod.POST, content, false, includeResponseDetails, includeResponseBody);
	}

	/**
	 * Available HTTPMethods
	 */
	protected enum HttpMethod {
		/** GET method */
		GET,
		/** POST method */
		POST
	}

}
