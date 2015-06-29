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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Document;

/**
 * AsicManifest file representation
 *
 *
 */

public class AsicManifestDocument extends CommonDocument {

	private byte[] bytes;

	private String name;

	private String absolutePath;

	private String signatureUri;

	/**
	 * Creates dss document that retains the data in memory
	 *
	 * @param bytes array of bytes representing the document
	 * @param name  the file name if the data originates from a file
	 */
	public AsicManifestDocument(final byte[] bytes, final String name) {

		this.bytes = bytes;
		this.name = name;
		this.mimeType = MimeType.XML;
		final Document document = DSSXMLUtils.buildDOM(bytes);
		signatureUri = DSSXMLUtils.getValue(document, "/asic:ASiCManifest/asic:SigReference/@URI");
		if (StringUtils.isBlank(signatureUri)) {
			throw new DSSException("The AsicManifest file must contains the URI of the related signature.");
		}
	}

	@Override
	public InputStream openStream() throws DSSException {

		final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
		return byteArrayInputStream;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public byte[] getBytes() throws DSSException {
		return bytes;
	}

	public void setName(final String name) {
		this.name = name;
	}

	public void setAbsolutePath(final String absolutePath) {
		this.absolutePath = absolutePath;
	}

	@Override
	public void save(final String filePath) {

		try {

			final FileOutputStream fos = new FileOutputStream(filePath);
			DSSUtils.write(getBytes(), fos);
			fos.close();
		} catch (FileNotFoundException e) {
			throw new DSSException(e);
		} catch (DSSException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public String getAbsolutePath() {

		return absolutePath;
	}

	@Override
	public String getDigest(final DigestAlgorithm digestAlgorithm) {
		final byte[] digestBytes = DSSUtils.digest(digestAlgorithm, bytes);
		final String base64Encode = Base64.encodeBase64String(digestBytes);
		return base64Encode;
	}

	@Override
	public String getBase64Encoded() {
		return Base64.encodeBase64String(bytes);
	}

	public String getSignatureUri() {
		return signatureUri;
	}
}