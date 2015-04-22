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
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
class PdfBoxDocTimestampInfo extends PdfBoxCMSInfo implements PdfDocTimestampInfo {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxDocTimestampInfo.class);

	private final TimestampToken timestampToken;

	/**
	 * @param validationCertPool
	 * @param outerCatalog       the PDF Dict of the outer document, if the PDFDocument in a enclosed revision. Can be null.
	 * @param document           the signed PDFDocument
	 * @param cms                the CMS (CAdES) bytes
	 * @param inputStream        the stream of the whole signed document
	 * @throws IOException
	 */
	PdfBoxDocTimestampInfo(CertificatePool validationCertPool, PdfBoxDict outerCatalog, PDDocument document, PDSignature signature, byte[] cms, InputStream inputStream) throws DSSException, IOException {
		super(validationCertPool, outerCatalog, document, signature, cms, inputStream);
		try {
			TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(cms));

			TimestampType timestampType = TimestampType.SIGNATURE_TIMESTAMP;
			if (document.getDocumentCatalog().getCOSDictionary().containsKey("DSS")) {
				timestampType = TimestampType.ARCHIVE_TIMESTAMP;
			}
			timestampToken = new TimestampToken(timeStampToken, timestampType, validationCertPool);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Created PdfBoxDocTimestampInfo {}: {}", timestampType, uniqueId());
			}
		} catch (CMSException e) {
			throw new DSSException(e);
		} catch (TSPException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public SignatureCryptographicVerification checkIntegrityOnce() {

		final SignatureCryptographicVerification signatureCryptographicVerification = new SignatureCryptographicVerification();
		signatureCryptographicVerification.setReferenceDataFound(false);
		signatureCryptographicVerification.setReferenceDataIntact(false);
		signatureCryptographicVerification.setSignatureIntact(false);
		if (signedBytes != null) {
			signatureCryptographicVerification.setReferenceDataFound(true);
		}
		signatureCryptographicVerification.setReferenceDataIntact(timestampToken.matchData(signedBytes));
		signatureCryptographicVerification.setSignatureIntact(timestampToken.isSignatureValid());
		return signatureCryptographicVerification;
	}

	@Override
	public X509Certificate getSigningCertificate() {

		final CertificateToken signingCertificate = timestampToken.getIssuerToken();
		return signingCertificate == null ? null : signingCertificate.getCertificate();
	}

	@Override
	public X509Certificate[] getCertificates() {
		final List<CertificateToken> certificateTokens = timestampToken.getCertificates();
		return toX509CertificateArray(certificateTokens);
	}

	@Override
	public boolean isTimestamp() {
		return true;
	}

	@Override
	public TimestampToken getTimestampToken() {
		return timestampToken;
	}
}
