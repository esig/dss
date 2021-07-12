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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Implementation of native java DataLoader using the java.net.URL class.
 *
 */
public class NativeHTTPDataLoader implements DataLoader {

	private static final long serialVersionUID = 4075489539157157286L;

	/**
	 * Available HTTPMethods
	 */
	protected enum HttpMethod {
		/** GET method */
		GET,
		/** POST method */
		POST
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(NativeHTTPDataLoader.class);

	/** Max inputStream size */
	private long maxInputSize;

	/**
	 * Timeout of the full request processing time (send and retrieve data).
	 */
	private long timeout = 0;

	/**
	 * Execute the request
	 *
	 * @param url {@link String}
	 * @param method {@link HttpMethod}
	 * @param content request content
	 * @param refresh if enforce the refresh
	 * @return response binaries
	 */
	protected byte[] request(String url, HttpMethod method, byte[] content, boolean refresh) {
		NativeDataLoaderCall task = new NativeDataLoaderCall(url, content, refresh, maxInputSize);

		ExecutorService executorService = Executors.newSingleThreadExecutor();
		try {
			Future<byte[]> result = executorService.submit(task);
			return timeout > 0 ? result.get(timeout, TimeUnit.MILLISECONDS) : result.get();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new DSSExternalResourceException(e);
		} catch (ExecutionException | TimeoutException e) {
			throw new DSSExternalResourceException(e);
		} finally {
			executorService.shutdown();
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
				LOGGER.warn("Impossible to obtain data using {}", urlString, e);
			}
		}
		throw new DSSExternalResourceException(String.format("No data have been obtained from urls : %s", urlStrings));
	}

	@Override
	public byte[] get(String url) {
		return get(url, false);
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		return request(url, HttpMethod.GET, null, !refresh);
	}

	@Override
	public byte[] post(String url, byte[] content) {
		return request(url, HttpMethod.POST, content, false);
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
	public long getMaxInputSize() {
		return maxInputSize;
	}

	/**
	 * Sets the maximum InputStream size
	 *
	 * @param maxInputSize maximum InputStream size
	 */
	public void setMaxInputSize(long maxInputSize) {
		this.maxInputSize = maxInputSize;
	}

	/**
	 * Gets timeout value
	 *
	 * @return timeout value
	 */
	public long getTimeout() {
		return timeout;
	}

	/**
	 * Sets timeout value
	 *
	 * @param timeout timeout value
	 */
	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}

}
