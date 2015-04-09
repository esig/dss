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
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

class PdfBoxSignatureInfo extends PdfBoxCMSInfo implements PdfSignatureInfo {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxSignatureInfo.class);
	private CAdESSignature cades;

	/**
	 * @param validationCertPool
	 * @param outerCatalog       the PDF Dict of the outer document, if the PDFDocument in a enclosed revision. Can be null.
	 * @param document           the signed PDFDocument
	 * @param cms                the CMS (CAdES) bytes
	 * @param inputStream        the stream of the whole signed document
	 * @throws IOException
	 */
	PdfBoxSignatureInfo(CertificatePool validationCertPool, PdfDict outerCatalog, PDDocument document, PDSignature signature, byte[] cms,
			InputStream inputStream) throws IOException {
		super(validationCertPool, outerCatalog, document, signature, cms, inputStream);
		try {
			cades = new CAdESSignature(cms, validationCertPool);
			final InMemoryDocument detachedContent = new InMemoryDocument(signedBytes);
			cades.setDetachedContents(detachedContent);
			cades.setPadesSigningTime(getSigningDate());
		} catch (CMSException e) {
			throw new IOException(e);
		}
	}

	@Override
	protected SignatureCryptographicVerification checkIntegrityOnce() {
		return cades.checkSignatureIntegrity();
	}

	@Override
	public X509Certificate getSigningCertificate() {
		CertificateToken signingCertificate = cades.getSigningCertificateToken();
		return signingCertificate == null ? null : signingCertificate.getCertificate();
	}

	@Override
	public X509Certificate[] getCertificates() {
		final List<CertificateToken> certificates = cades.getCertificates();
		return toX509CertificateArray(certificates);

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
}
