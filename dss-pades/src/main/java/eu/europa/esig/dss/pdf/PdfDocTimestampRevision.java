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
import java.util.List;

import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

/**
 * Signature timestamp representation
 * This class is only used in case of Document Timestamp (not signature-timestamp from CAdES/CMS)
 */
public class PdfDocTimestampRevision extends PdfCMSRevision {

	private static final Logger LOG = LoggerFactory.getLogger(PdfDocTimestampRevision.class);

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
	public PdfDocTimestampRevision(byte[] cms, PdfSignatureDictionary signatureDictionary, PdfDssDict timestampedDssDictionary, 
			List<String> timestampFieldNames, CertificatePool validationCertPool, byte[] signedContent, boolean coverCompleteRevision) {
		super(cms, signatureDictionary, timestampedDssDictionary, timestampFieldNames, signedContent, coverCompleteRevision);
		try {
			TimestampType timestampType = TimestampType.SIGNATURE_TIMESTAMP;
			if (timestampedDssDictionary != null) {
				timestampType = TimestampType.ARCHIVE_TIMESTAMP;
			}
			timestampToken = new TimestampToken(this, timestampType, validationCertPool, TimestampLocation.DOC_TIMESTAMP);
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
		byte[] signedDocumentContent = getSignedDocumentBytes();
		signatureCryptographicVerification.setReferenceDataIntact(timestampToken.matchData(new InMemoryDocument(signedDocumentContent)));
		signatureCryptographicVerification.setSignatureIntact(timestampToken.isSignatureValid());
	}

	@Override
	public boolean isTimestampRevision() {
		return true;
	}

	@Override
	public Date getSigningDate() {
		return timestampToken.getGenerationTime();
	}

	public TimestampToken getTimestampToken() {
		return timestampToken;
	}

	@Override
	protected boolean isSignerInformationValidated(SignerInformation signerInformation) {
		return signerInformation == timestampToken.getSignerInformation();
	}

}
