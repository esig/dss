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
package eu.europa.esig.dss.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.validation.report.SimpleReport;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.TimestampType;

public abstract class AbstractTestSignature {

	private static final Logger logger = LoggerFactory.getLogger(AbstractTestSignature.class);

	protected abstract DSSDocument getDocumentToSign();

	protected abstract DocumentSignatureService getService();

	protected abstract MockPrivateKeyEntry getPrivateKeyEntry();

	protected abstract AbstractSignatureParameters getSignatureParameters();

	protected abstract MimeType getExpectedMime();

	protected abstract boolean isBaselineT();

	protected abstract boolean isBaselineLTA();

	@Test
	public void signAndVerify() throws IOException {
		final DSSDocument signedDocument = sign();

		logger.info("=================== VALIDATION =================");

		// signedDocument.save("target/cades-b.bin");

		if (logger.isDebugEnabled()) {
			try {
				byte[] byteArray = IOUtils.toByteArray(signedDocument.openStream());
				onDocumentSigned(byteArray);
				// LOGGER.debug(new String(byteArray));
			} catch (Exception e) {
				logger.error("Cannot display file content", e);
			}
		}

		checkMimeType(signedDocument);

		Reports reports = getValidationReport(signedDocument);

		if (logger.isDebugEnabled()) {
			reports.print();
		}

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		verifyDiagnosticData(diagnosticData);

		SimpleReport simpleReport = reports.getSimpleReport();
		verifySimpleReport(simpleReport);
	}

	protected void onDocumentSigned(byte[] byteArray) {
	}

	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		checkBLevelValid(diagnosticData);
		checkNumberOfSignatures(diagnosticData);
		checkDigestAlgorithm(diagnosticData);
		checkEncryptionAlgorithm(diagnosticData);
		checkSigningCertificateValue(diagnosticData);
		checkIssuerSigningCertificateValue(diagnosticData);
		checkCertificateChain(diagnosticData);
		checkSignatureLevel(diagnosticData);
		checkSigningDate(diagnosticData);
		checkTLevelAndValid(diagnosticData);
		checkALevelAndValid(diagnosticData);
		checkTimestamps(diagnosticData);
	}

	protected void verifySimpleReport(SimpleReport simpleReport) {
		assertNotNull(simpleReport);
	}

	protected DSSDocument sign() {
		DSSDocument toBeSigned = getDocumentToSign();
		AbstractSignatureParameters params = getSignatureParameters();
		DocumentSignatureService service = getService();
		MockPrivateKeyEntry privateKeyEntry = getPrivateKeyEntry();

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = TestUtils.sign(params.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		final DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		return signedDocument;
	}

	protected Reports getValidationReport(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		// TODO uncomment when DSS-666 is done
		// List<AdvancedSignature> signatures = validator.getSignatures();
		// assertTrue(CollectionUtils.isNotEmpty(signatures));

		Reports reports = validator.validateDocument();
		return reports;
	}

	protected void checkMimeType(DSSDocument signedDocument) {
		assertEquals(getExpectedMime(), signedDocument.getMimeType());
	}

	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(1, CollectionUtils.size(diagnosticData.getSignatureIdList()));
	}

	protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
		assertEquals(getPrivateKeyEntry().getCertificate().getDigestAlgorithm(),
				diagnosticData.getSignatureDigestAlgorithm(diagnosticData.getFirstSignatureId()));
	}

	private void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
		assertEquals(getSignatureParameters().getSignatureAlgorithm().getEncryptionAlgorithm(),
				diagnosticData.getSignatureEncryptionAlgorithm(diagnosticData.getFirstSignatureId()));
	}

	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		String signingCertificateId = diagnosticData.getSigningCertificateId();
		String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
		String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
		CertificateToken certificate = getPrivateKeyEntry().getCertificate();
		// Remove space, normal ?
		assertEquals(certificate.getSubjectDN().getName().replace(" ", ""), certificateDN.replace(" ", ""));
		assertEquals(certificate.getSerialNumber().toString(), certificateSerialNumber);
	}

	protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
		String signingCertificateId = diagnosticData.getSigningCertificateId();
		String issuerDN = diagnosticData.getCertificateIssuerDN(signingCertificateId);
		CertificateToken certificate = getPrivateKeyEntry().getCertificate();
		// Remove space, normal ?
		assertEquals(certificate.getIssuerDN().getName().replace(" ", ""), issuerDN.replace(" ", ""));
	}

	private void checkCertificateChain(DiagnosticData diagnosticData) {
		DSSPrivateKeyEntry privateKeyEntry = getPrivateKeyEntry();
		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		// TODO what is correct ? signing certificate is in the chain or only
		// parents ?
		assertEquals(privateKeyEntry.getCertificateChain().length, signatureCertificateChain.size() - 1);
	}

	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(getSignatureParameters().getSignatureLevel().name(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected void checkTLevelAndValid(DiagnosticData diagnosticData) {
		assertEquals(isBaselineT(), diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
		assertEquals(isBaselineT(), diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected void checkALevelAndValid(DiagnosticData diagnosticData) {
		assertEquals(isBaselineLTA(), diagnosticData.isThereALevel(diagnosticData.getFirstSignatureId()));
		assertEquals(isBaselineLTA(), diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());

		boolean foundSignatureTimeStamp = false;
		boolean foundArchiveTimeStamp = false;

		if ((timestampIdList != null) && (timestampIdList.size() > 0)) {
			for (String timestampId : timestampIdList) {
				String timestampType = diagnosticData.getTimestampType(timestampId);
				TimestampType type = TimestampType.valueOf(timestampType);
				switch (type) {
					case SIGNATURE_TIMESTAMP:
						foundSignatureTimeStamp = true;
						break;
					case ARCHIVE_TIMESTAMP:
						foundArchiveTimeStamp = true;
						break;
					default:
						break;
				}

			}
		}

		if (isBaselineT()) {
			assertTrue(foundSignatureTimeStamp);
		}

		if (isBaselineLTA()) {
			assertTrue(foundArchiveTimeStamp);
		}

	}

	protected void checkSigningDate(DiagnosticData diagnosticData) {
		Date signatureDate = diagnosticData.getSignatureDate();
		Date originalSigningDate = getSignatureParameters().bLevel().getSigningDate();

		try {
			// Time in GMT
			SimpleDateFormat dateFormatGmt = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");
			dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
			SimpleDateFormat dateFormatLocal = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");
			Date originalGMTDate = dateFormatLocal.parse(dateFormatGmt.format(originalSigningDate));

			assertEquals(originalGMTDate, signatureDate);
		} catch (ParseException e) {
			fail("Cannot check the signing date");
		}
	}
}
