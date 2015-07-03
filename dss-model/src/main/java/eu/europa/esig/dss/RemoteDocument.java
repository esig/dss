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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * This class is used to transport a DSSDocument with SOAP and/or REST
 */
@SuppressWarnings("serial")
public class RemoteDocument extends CommonDocument {

	private byte[] bytes;
	private String name = "RemoteDocument";
	private String absolutePath = "RemoteDocument";

	public RemoteDocument(DSSDocument document) {
		byte[] bytes = document.getBytes();
		this.bytes = Arrays.copyOf(bytes, bytes.length);
		this.mimeType = document.getMimeType();
		this.name = document.getName();
		this.absolutePath = document.getAbsolutePath();

		DSSDocument nextDssDocument = document.getNextDocument();
		if (nextDssDocument != null) {
			this.nextDocument = new RemoteDocument(nextDssDocument);
		}
	}

	@Override
	public InputStream openStream() throws DSSException {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
		return byteArrayInputStream;
	}

	@Override
	public byte[] getBytes() {
		return bytes;
	}

	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	@Override
	public String getName() {
		return name;
	}

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
	public void save(String filePath) throws IOException {
		throw new DSSException("Not implemented !");
	}

	@Override
	public String getDigest(DigestAlgorithm digestAlgorithm) {
		throw new DSSException("Not implemented !");
	}

	@Override
	public String getBase64Encoded() {
		throw new DSSException("Not implemented !");
	}

}
