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

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * Signature timestamp representation
 * This class is only used in case of Document Timestamp (not signature-timestamp from CAdES/CMS)
 */
class PdfBoxDocTimestampInfo extends PdfBoxCMSInfo implements PdfDocTimestampInfo {

	private static final Logger logger = LoggerFactory.getLogger(PdfBoxDocTimestampInfo.class);

	private final TimestampToken timestampToken;

	private final byte[] content;

	/**
	 * @param validationCertPool
	 * @param dssDictionary
	 *            the DSS dictionary
	 * @param cms
	 *            the CMS (CAdES) bytes
	 * @param isArchiveTimestamp
	 * @param inputStream
	 *            the stream of the whole signed document
	 * @throws DSSException
	 */
	PdfBoxDocTimestampInfo(CertificatePool validationCertPool, PDSignature signature, PdfDssDict dssDictionary, byte[] cms, byte[] signedContent,
			boolean isArchiveTimestamp) throws DSSException {
		super(signature, dssDictionary, cms, signedContent);
		try {
			TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(cms));
			TimestampType timestampType = TimestampType.SIGNATURE_TIMESTAMP;
			if (isArchiveTimestamp) {
				timestampType = TimestampType.ARCHIVE_TIMESTAMP;
			}
			timestampToken = new TimestampToken(timeStampToken, timestampType, validationCertPool);
			content = cms;
			logger.debug("Created PdfBoxDocTimestampInfo {} : {}", timestampType, uniqueId());
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	public void checkIntegrityOnce() {
		final SignatureCryptographicVerification signatureCryptographicVerification = new SignatureCryptographicVerification();
		signatureCryptographicVerification.setReferenceDataFound(false);
		signatureCryptographicVerification.setReferenceDataIntact(false);
		signatureCryptographicVerification.setSignatureIntact(false);
		if (getSignedDocumentBytes() != null) {
			signatureCryptographicVerification.setReferenceDataFound(true);
		}
		signatureCryptographicVerification.setReferenceDataIntact(timestampToken.matchData(getSignedDocumentBytes()));
		signatureCryptographicVerification.setSignatureIntact(timestampToken.isSignatureValid());
	}

	@Override
	public boolean isTimestamp() {
		return true;
	}

	@Override
	public TimestampToken getTimestampToken() {
		return timestampToken;
	}

	@Override
	public byte[] getContent() {
		return content;
	}

}