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

import java.io.IOException;
import java.io.InputStream;

/**
 * Used to limit the size of fetched data.
 */
public class MaxSizeInputStream extends InputStream {

	/** The maximum InputStream size */
	private long maxSize;

	/** The wrapped InputStream */
	private InputStream wrappedStream;

	/** The requested URL */
	private String url;

	/** The counter */
	private long count = 0;

	/**
	 * The default constructor for NativeHTTPDataLoader.MaxSizeInputStream.
	 * 
	 * @param wrappedStream
	 *            the wrapped stream
	 * @param maxSize
	 *            the maximum size to read
	 * @param url
	 *            the url source
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
				throw new IOException("Cannot fetch data limit=" + maxSize + ", url =" + url);
			}
		}
		return wrappedStream.read();
	}

}
