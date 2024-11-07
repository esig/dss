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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Used to limit the size of fetched data. Throws {@code IOException} if the data limit has been reached.
 * Inspired by {@code org.apache.commons.fileupload.util.LimitedInputStream}
 *
 */
public class MaxSizeInputStream extends FilterInputStream {

	/** The maximum InputStream size */
	private final int maxSize;

	/** The requested URL */
	private final String url;

	/** The counter */
	private int count = 0;

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
	public MaxSizeInputStream(InputStream wrappedStream, int maxSize, String url) {
		super(wrappedStream);
		Objects.requireNonNull(wrappedStream, "InputStream shall be provided!");
		this.url = url;
		this.maxSize = maxSize;
	}

	@Override
	public int read() throws IOException {
		int b = super.read();
		if (b != -1) {
			++count;
			checkSize();
		}
		return b;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int read = super.read(b, off, len);
		if (read > 0) {
			count += read;
			checkSize();
		}
		return read;
	}

	private void checkSize() throws IOException {
		if (maxSize != 0 && count > maxSize) {
			throw new IOException("Cannot fetch data limit=" + maxSize + ", url=" + url);
		}
	}

}
