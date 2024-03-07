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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1334SignatureTest extends AbstractXAdESTestSignature {

	private static final DSSDocument ORIGINAL_FILE = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = ORIGINAL_FILE;
		documentToSign.setName(null);

		service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
	}

	@Test
	public void extendValidFile() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/simple-test-signed-xades-baseline-b.xml");

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());

		XAdESService service = new XAdESService(certificateVerifier);
		service.setTspSource(getGoodTsa());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parameters.setDetachedContents(Arrays.asList(ORIGINAL_FILE));
		
		DSSDocument extendedDocument = service.extendDocument(doc, parameters);
		assertNotNull(extendedDocument);
	}

	@Test
	public void extendInvalidFile() {
		DSSDocument doc = new FileDocument(
				"src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);
		service.setTspSource(getGoodTsa());

		certificateVerifier.setAlertOnInvalidSignature(new ExceptionOnStatusAlert());

		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parameters.setDetachedContents(Arrays.asList(ORIGINAL_FILE));
		Exception exception = assertThrows(AlertException.class, () -> service.extendDocument(doc, parameters));
		assertTrue(exception.getMessage().contains("Error on signature augmentation."));
		assertTrue(exception.getMessage().contains("Cryptographic signature verification has failed / Signature verification failed against the best candidate."));

		certificateVerifier.setAlertOnInvalidSignature(new SilentOnStatusAlert());

		exception = assertThrows(AlertException.class, () -> service.extendDocument(doc, parameters));
		assertTrue(exception.getMessage().contains("Error on signature augmentation."));
		assertTrue(exception.getMessage().contains("is expired at signing time"));

		certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());

		DSSDocument extendedDocument = service.extendDocument(doc, parameters);
		assertNotNull(extendedDocument);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		List<TimestampWrapper> timestampList = signature.getTimestampList();
		assertEquals(1, timestampList.size());

		assertFalse(signature.isBLevelTechnicallyValid());

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

		exception = assertThrows(AlertException.class, () -> service.extendDocument(doc, parameters));
		assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));

		certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());

		extendedDocument = service.extendDocument(doc, parameters);
		assertNotNull(extendedDocument);

		validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(certificateVerifier);
		reports = validator.validateDocument();

		diagnosticData = reports.getDiagnosticData();
		signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		timestampList = signature.getTimestampList();
		assertEquals(1, timestampList.size());
		assertTrue(Utils.isCollectionNotEmpty(signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES)));

		assertFalse(signature.isBLevelTechnicallyValid());

		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		extendedDocument = service.extendDocument(doc, parameters);
		assertNotNull(extendedDocument);

		validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(certificateVerifier);
		reports = validator.validateDocument();

		diagnosticData = reports.getDiagnosticData();
		signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		timestampList = signature.getTimestampList();
		assertEquals(2, timestampList.size());
		assertTrue(Utils.isCollectionNotEmpty(signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES)));

		assertFalse(signature.isBLevelTechnicallyValid());
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(ORIGINAL_FILE);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
