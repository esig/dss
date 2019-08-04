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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.Callable;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.utils.Utils;

public class NativeDataLoaderCall implements Callable<byte[]> {

	private static final String ERROR_MESSAGE = "An error occured while reading from url '%s' : %s";
	
	private String url;
	private byte[] content;
	private long maxInputSize;

	private boolean useCaches;

	public NativeDataLoaderCall(String url, byte[] content, boolean useCaches, long maxInputSize) {
		super();
		this.url = url;
		this.content = content;
		this.useCaches = useCaches;
		this.maxInputSize = maxInputSize;
	}
	
	public byte[] call() {
		OutputStream out = null;
		InputStream inputStream = null;
		byte[] result = null;
		try {
			URLConnection connection = createConnection();

			connection.setUseCaches(useCaches);
			connection.setDoInput(true);
			if (content != null) {
				connection.setDoOutput(true);
				out = connection.getOutputStream();
				Utils.write(content, out);
			}
			inputStream = connection.getInputStream();
			result = Utils.toByteArray(maxInputSize > 0? new MaxSizeInputStream(inputStream, maxInputSize, url): inputStream);
		} catch (IOException e) {
			throw new DSSException(String.format(ERROR_MESSAGE, url, e.getMessage()), e);
		} finally {
			Utils.closeQuietly(out);
			Utils.closeQuietly(inputStream);
		}
		return result;
	}

	protected URLConnection createConnection() throws MalformedURLException, IOException {
		return new URL(url).openConnection();
	}

	public String getUrl() {
		return url;
	}

	public byte[] getContent() {
		return content;
	}

	public long getMaxInputSize() {
		return maxInputSize;
	}

	public boolean isUseCaches() {
		return useCaches;
	}
}
