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
package eu.europa.esig.dss.cades.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.cms.CMSSignedData;

import eu.europa.esig.dss.CommonDocument;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;

/**
 * A document composed by a CMSSignedData
 */
public class CMSSignedDocument extends CommonDocument {

	protected CMSSignedData signedData;

	/**
	 * The default constructor for CMSSignedDocument.
	 *
	 * @param data
	 * @throws IOException
	 */
	public CMSSignedDocument(final CMSSignedData data) throws DSSException {
		this.signedData = data;
		if (data == null) {
			throw new NullPointerException();
		}
		mimeType = MimeType.PKCS7;
	}

	@Override
	public InputStream openStream() throws DSSException {
		final byte[] bytes = getBytes();
		final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
		return byteArrayInputStream;
	}

	/**
	 * @return the signedData
	 */
	public CMSSignedData getCMSSignedData() {
		return signedData;
	}

	public byte[] getBytes() throws DSSException {
		try {
			final ByteArrayOutputStream output = new ByteArrayOutputStream();
			final DEROutputStream derOutputStream = new DEROutputStream(output);
			final byte[] encoded = signedData.getEncoded();
			final ASN1Primitive asn1Primitive = DSSASN1Utils.toASN1Primitive(encoded);
			derOutputStream.writeObject(asn1Primitive);
			derOutputStream.close();
			return output.toByteArray();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public void save(final String filePath) {
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(filePath);
			Utils.write(getBytes(), fos);
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			Utils.closeQuietly(fos);
		}
	}

	@Override
	public String getDigest(final DigestAlgorithm digestAlgorithm) {
		final byte[] digestBytes = DSSUtils.digest(digestAlgorithm, getBytes());
		final String base64Encode = Utils.toBase64(digestBytes);
		return base64Encode;
	}

	public String getBase64Encoded() {
		return Utils.toBase64(getBytes());
	}

	@Override
	public String getAbsolutePath() {
		return super.getName();
	}

}
