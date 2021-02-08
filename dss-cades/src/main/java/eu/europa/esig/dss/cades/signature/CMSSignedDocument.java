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

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cms.CMSSignedData;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * A document composed by a CMSSignedData
 */
public class CMSSignedDocument extends CommonDocument {

	/**
	 * The CMSSignedData representing the document
	 */
	protected CMSSignedData signedData;

	/**
	 * The default constructor for CMSSignedDocument.
	 *
	 * @param data
	 *            the CMSSignedData
	 */
	public CMSSignedDocument(final CMSSignedData data) {
		Objects.requireNonNull(data, "The CMSSignedData cannot be null");
		this.signedData = data;
		this.mimeType = MimeType.PKCS7;
	}

	@Override
	public InputStream openStream() {
		return new ByteArrayInputStream(getBytes());
	}

	/**
	 * Gets {@code CMSSignedData}
	 *
	 * @return {@link CMSSignedData} the signedData
	 */
	public CMSSignedData getCMSSignedData() {
		return signedData;
	}

	public byte[] getBytes() {
		try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
			writeTo(output);
			return output.toByteArray();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		final byte[] encoded = signedData.getEncoded();
		final ASN1Primitive asn1Primitive = DSSASN1Utils.toASN1Primitive(encoded);
		final ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(stream, ASN1Encoding.DER);
		asn1OutputStream.writeObject(asn1Primitive);
	}

}
