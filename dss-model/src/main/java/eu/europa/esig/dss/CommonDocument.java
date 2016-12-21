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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;

/**
 * This class implements the default methods.
 *
 */
@SuppressWarnings("serial")
public abstract class CommonDocument implements DSSDocument {

	protected MimeType mimeType;

	protected String name;

	protected String absolutePath;

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		byte[] buffer = new byte[1024];
		int count = -1;
		InputStream inStream = openStream();
		while ((count = inStream.read(buffer)) > 0) {
			stream.write(buffer, 0, count);
		}
		inStream.close();
	}

	@Override
	public MimeType getMimeType() {
		return mimeType;
	}

	@Override
	public void setMimeType(final MimeType mimeType) {
		this.mimeType = mimeType;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String getAbsolutePath() {
		return absolutePath;
	}

	public void setAbsolutePath(String absolutePath) {
		this.absolutePath = absolutePath;
	}

	@Override
	public String toString() {

		final StringWriter stringWriter = new StringWriter();
		stringWriter.append("Name: " + getName()).append(" / ").append(mimeType == null ? "" : mimeType.getMimeTypeString()).append(" / ")
				.append(getAbsolutePath());
		final String string = stringWriter.toString();
		return string;
	}
}
