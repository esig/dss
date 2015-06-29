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

import java.io.StringWriter;

/**
 * This class implements the default methods.
 *
 *
 *
 *
 *
 */
public abstract class CommonDocument implements DSSDocument {

	protected DSSDocument nextDocument;

	protected MimeType mimeType;

	@Override
	public MimeType getMimeType() {
		return mimeType;
	}

	@Override
	public void setMimeType(final MimeType mimeType) {
		this.mimeType = mimeType;
	}

	@Override
	public DSSDocument getNextDocument() {
		return nextDocument;
	}

	@Override
	public void setNextDocument(final DSSDocument nextDocument) {
		this.nextDocument = nextDocument;
	}

	@Override
	public String toString() {

		final StringWriter stringWriter = new StringWriter();
		stringWriter.append("Name: " + getName()).append(" / ").append(mimeType == null ? "" : mimeType.getMimeTypeString()).append(" / ").append(getAbsolutePath());
		final String string = stringWriter.toString();
		return string;
	}
}
