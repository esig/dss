/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESExtensionAllSelfSignedCertsTest extends AbstractXAdESTestExtension {

	private SignatureLevel originalSignatureLevel;
	private SignatureLevel finalSignatureLevel;
	
	private DSSDocument documentToSign;
	private XAdESService service;
	private CertificateVerifier certificateVerifier;
	
	@BeforeEach
	void init() {
		documentToSign = new FileDocument("src/test/resources/sample.xml");

		certificateVerifier = getCompleteCertificateVerifier();
		service = new XAdESService(certificateVerifier);
        service.setTspSource(getSelfSignedTsa());
	}

	@Test
	void bToTTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		finalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void bToLTTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LT;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void tToLTTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LT;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void bToLTATest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LTA;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void tToLTATest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LTA;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void bToCTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_C;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void tToCTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_C;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void bToXTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_X;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void tToXTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_X;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void bToXLTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_XL;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void tToXLTest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_XL;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void bToATest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_A;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(3, reports.getDiagnosticData().getTimestampList().size());
	}

	@Test
	void tToATest() throws Exception {
		originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
		DSSDocument signedDocument = getSignedDocument(documentToSign);

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

		finalSignatureLevel = SignatureLevel.XAdES_A;
		Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
		assertTrue(exception.getMessage().contains("Error on signature augmentation to C-level."));
		assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

		certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

		DSSDocument extendedDocument = extendSignature(signedDocument);
		assertNotNull(extendedDocument);
		Reports reports = verify(extendedDocument);
		assertEquals(3, reports.getDiagnosticData().getTimestampList().size());
	}

	@Override
	protected XAdESService getSignatureServiceToSign() {
		return service;
	}

	@Override
	protected XAdESService getSignatureServiceToExtend() {
		return service;
	}

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return originalSignatureLevel;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return finalSignatureLevel;
	}

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

	@Override
	public void extendAndVerify() throws Exception {
		// do nothing
	}

}
