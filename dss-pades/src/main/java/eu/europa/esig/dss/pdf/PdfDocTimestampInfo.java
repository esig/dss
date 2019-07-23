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
package eu.europa.esig.dss.pdf;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.x509.CertificatePool;

/**
 * Signature timestamp representation
 * This class is only used in case of Document Timestamp (not signature-timestamp from CAdES/CMS)
 */
public class PdfDocTimestampInfo extends PdfCMSInfo implements PdfSignatureOrDocTimestampInfo {

	private static final Logger LOG = LoggerFactory.getLogger(PdfDocTimestampInfo.class);

	private final TimestampToken timestampToken;

	/**
	 * Default constructor to create PdfDocTimestampInfo
	 * 
	 * @param validationCertPool
	 *                                 the certificate pool
	 * @param signatureDictionary
	 *                                 the signature dictionary
	 * @param timestampedDssDictionary
	 *                                 the covered DSS dictionary
	 * @param cms
	 *                                 the CMS (CAdES) bytes
	 * @param signedContent
	 *                                 the signed data
	 * @param coverCompleteRevision
	 *                                 true if the signature covers all bytes
	 */
	public PdfDocTimestampInfo(CertificatePool validationCertPool, PdfSigDict signatureDictionary,
			PdfDssDict timestampedDssDictionary, byte[] cms, byte[] signedContent, boolean coverCompleteRevision) {
		super(signatureDictionary, timestampedDssDictionary, cms, signedContent, coverCompleteRevision);
		try {
			TimestampType timestampType = TimestampType.SIGNATURE_TIMESTAMP;
			if (timestampedDssDictionary != null) {
				timestampType = TimestampType.ARCHIVE_TIMESTAMP;
			}
			timestampToken = new TimestampToken(cms, timestampType, validationCertPool, TimestampLocation.DOC_TIMESTAMP);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Created PdfDocTimestampInfo {} : {}", timestampType, uniqueId());
			}
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
	public Date getSigningDate() {
		return timestampToken.getGenerationTime();
	}

	public TimestampToken getTimestampToken() {
		return timestampToken;
	}

}
