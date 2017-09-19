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
package eu.europa.esig.dss;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;

/**
 * TODO
 *
 *
 *
 *
 *
 */
public class ResourceLoader {

	protected Class<?> anyClass = ResourceLoader.class;

	public ResourceLoader() {
	}

	/**
	 * It can be used when there is a need to change the class loader.
	 *
	 * @param anyClass
	 */
	public ResourceLoader(Class<?> anyClass) {
		this.anyClass = anyClass;
	}

	public static String getNormalizedFileName(final String fileName) {
		final String normalizedFileName = fileName.replaceAll("\\W", "_");
		return normalizedFileName;
	}

	/**
	 * This method converts the resource path to the absolute path in target folder.
	 *
	 * @param resourcePath
	 *            resource path
	 * @return
	 */
	public String getAbsoluteResourceFolder(final String resourcePath) throws DSSException {
		final URL uri = anyClass.getResource(resourcePath);
		if (uri == null) {
			return null;
		}
		final String absolutePath = uri.getPath();
		try {
			final String decodedAbsolutePath = URLDecoder.decode(absolutePath, "UTF-8");
			return decodedAbsolutePath;
		} catch (UnsupportedEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method converts the resource path to the input stream.
	 *
	 * @param resourcePath
	 * @return
	 */
	public InputStream getResource(final String resourcePath) {
		final InputStream resourceAsStream = anyClass.getResourceAsStream(resourcePath);
		return resourceAsStream;
	}

}
