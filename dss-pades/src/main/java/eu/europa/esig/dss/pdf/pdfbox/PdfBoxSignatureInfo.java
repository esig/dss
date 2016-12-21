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
package eu.europa.esig.dss.pdf.pdfbox;

import java.io.IOException;
import java.util.Arrays;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.x509.CertificatePool;

class PdfBoxSignatureInfo extends PdfBoxCMSInfo implements PdfSignatureInfo {

	private final CAdESSignature cades;

	private final byte[] content;

	/**
	 * @param validationCertPool
	 * @param dssDictionary
	 *            the DSS dictionary
	 * @param cms
	 *            the CMS (CAdES) bytes
	 * @param originalBytes
	 *            the original bytes of the whole signed document
	 * @throws IOException
	 */
	PdfBoxSignatureInfo(CertificatePool validationCertPool, PDSignature signature, PdfDssDict dssDictionary, byte[] cms, byte[] originalBytes)
			throws IOException {
		super(signature, dssDictionary, cms, originalBytes);
		try {
			cades = new CAdESSignature(cms, validationCertPool);
			content = cms;
			final DSSDocument detachedContent = new InMemoryDocument(getSignedDocumentBytes());
			cades.setDetachedContents(Arrays.asList(detachedContent));
		} catch (CMSException e) {
			throw new IOException(e);
		}
	}

	@Override
	protected void checkIntegrityOnce() {
		cades.checkSignatureIntegrity();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof PdfBoxSignatureInfo)) {
			return false;
		}
		if (!super.equals(o)) {
			return false;
		}

		PdfBoxSignatureInfo that = (PdfBoxSignatureInfo) o;

		if (!cades.equals(that.cades)) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = (31 * result) + cades.hashCode();
		return result;
	}

	@Override
	public boolean isTimestamp() {
		return false;
	}

	@Override
	public CAdESSignature getCades() {
		return cades;
	}

	@Override
	public byte[] getContent() {
		return content;
	}

}