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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package eu.europa.esig.dss.client.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSCannotFetchDataException;
import eu.europa.esig.dss.DSSCannotFetchDataException.MSG;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.utils.Utils;

/**
 * Implementation of HTTPDataLoader that use the java.net.URL class.
 *
 */
public class NativeHTTPDataLoader implements DataLoader {

	private static Logger logger = LoggerFactory.getLogger(NativeHTTPDataLoader.class);

	private static final long MAX_SIZE = 15000;

	/**
	 * Used to limit the size of fetched data.
	 */
	private class MaxSizeInputStream extends InputStream {

		private long maxSize;

		private InputStream wrappedStream;

		private long count = 0;

		private String url;

		/**
		 * The default constructor for NativeHTTPDataLoader.MaxSizeInputStream.
		 */
		public MaxSizeInputStream(InputStream wrappedStream, long maxSize, String url) {
			this.maxSize = maxSize;
			this.wrappedStream = wrappedStream;
			this.url = url;
		}

		@Override
		public int read() throws IOException {
			if (maxSize != 0) {
				count++;
				if (count > maxSize) {
					throw new DSSCannotFetchDataException(MSG.SIZE_LIMIT_EXCEPTION, url);
				}
			}
			return wrappedStream.read();
		}

	}

	@Override
	public byte[] get(String url) {
		InputStream inputStream = null;
		byte[] result = null;
		try {
			inputStream = new MaxSizeInputStream(new URL(url).openStream(), MAX_SIZE, url);
			result = Utils.toByteArray(inputStream);
		} catch (IOException e) {
			throw new DSSException("An error occured while HTTP GET for url '" + url + "' : " + e.getMessage(), e);
		} finally {
			Utils.closeQuietly(inputStream);
		}
		return result;
	}

	@Override
	public byte[] post(String url, byte[] content) {
		OutputStream out = null;
		InputStream inputStream = null;
		byte[] result = null;
		try {
			URLConnection connection = new URL(url).openConnection();

			connection.setDoInput(true);
			connection.setDoOutput(true);
			connection.setUseCaches(false);

			out = connection.getOutputStream();
			Utils.write(content, out);
			inputStream = connection.getInputStream();
			result = Utils.toByteArray(inputStream);
		} catch (IOException e) {
			throw new DSSException("An error occured while HTTP POST for url '" + url + "' : " + e.getMessage(), e);
		} finally {
			Utils.closeQuietly(out);
			Utils.closeQuietly(inputStream);
		}
		return result;
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {

		final int numberOfUrls = urlStrings.size();
		int ii = 0;
		for (final String urlString : urlStrings) {
			try {

				ii++;
				final byte[] bytes = get(urlString);
				if (bytes == null) {
					continue;
				}
				return new DataAndUrl(bytes, urlString);
			} catch (Exception e) {
				if (ii == numberOfUrls) {
					if (e instanceof DSSException) {
						throw (DSSException) e;
					}
					throw new DSSException(e);
				}
				logger.warn("Impossible to obtain data using {}", urlString, e);
			}
		}
		return null;
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		// set cache = false;
		return get(url);
	}

	@Override
	public void setContentType(String contentType) {
		throw new DSSException("Not implemented");
	}

}