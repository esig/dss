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
package eu.europa.esig.dss.client.http;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;

/**
 * Implementation of native java DataLoader using the java.net.URL class.
 *
 */
public class NativeHTTPDataLoader implements DataLoader {

	public enum HttpMethod {
		GET, POST
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(NativeHTTPDataLoader.class);

	private long maxInputSize;

	/**
	 * Timeout of the full request processing time (send and retrieve data).
	 */
	private long timeout = 0;

	protected byte[] request(String url, HttpMethod method, byte[] content, boolean refresh) {
		NativeDataLoaderCall task = new NativeDataLoaderCall(url, content, refresh, maxInputSize);

		ExecutorService executorService = Executors.newSingleThreadExecutor();
		try {
			Future<byte[]> result = executorService.submit(task);
			return timeout > 0 ? result.get(timeout, TimeUnit.MILLISECONDS) : result.get();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new DSSException(e);
		} catch (ExecutionException | TimeoutException e) {
			throw new DSSException(e);
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
					return new DataAndUrl(bytes, urlString);
				}
			} catch (Exception e) {
				LOGGER.warn("Impossible to obtain data using {}", urlString, e);
			}
		}
		throw new DSSException(String.format("Impossible to obtain data using with given urls %s", urlStrings));
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
		throw new DSSException("Not implemented");
	}

	public long getMaxInputSize() {
		return maxInputSize;
	}

	public void setMaxInputSize(long maxInputSize) {
		this.maxInputSize = maxInputSize;
	}

	public long getTimeout() {
		return timeout;
	}

	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}
}
