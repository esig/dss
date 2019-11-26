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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1419Test {

	@Test
	public void testSHA3_0() {
		// CAdES-BpB-att-SHA256-SHA3_256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA256-SHA3_256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA256, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_256, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());

		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_1() {
		// CAdES-BpB-att-SHA256-SHA3_256withRSAandMGF1.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA256-SHA3_256withRSAandMGF1.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA256, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_256, cades.getDigestAlgorithm());
		assertEquals(MaskGenerationFunction.MGF1, cades.getMaskGenerationFunction());

		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_2() {
		// CAdES-BpB-att-SHA3_224-SHA256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_224-SHA256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA3_224, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA256, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());

		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_3() {
		// CAdES-BpB-att-SHA3_256-SHA256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_256-SHA256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA3_256, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA256, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());

		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_4() {
		// CAdES-BpB-att-SHA3_256-SHA3_256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_256-SHA3_256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA3_256, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_256, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_5() {
		// CAdES-BpB-att-SHA3_384-SHA256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_384-SHA256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA3_384, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA256, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());

		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_6() {
		// CAdES-BpB-att-SHA3_512-SHA256withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_512-SHA256withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA3_512, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA256, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_7() {
		// CAdES-BpB-att-SHA256-SHA512withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA256-SHA512withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA256, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA512, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_8() {
		// CAdES-BpB-att-SHA3_224-SHA3_224withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_224-SHA3_224withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA3_224, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_224, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_9() {
		// CAdES-BpB-att-SHA3_512-SHA3_512withRSA.p7m
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-1419/CAdES-BpB-att-SHA3_512-SHA3_512withRSA.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		CAdESSignature cades = (CAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = cades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA3_512, messageDigestAlgorithms.iterator().next());
		assertNotNull(cades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, cades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_512, cades.getDigestAlgorithm());
		assertNull(cades.getMaskGenerationFunction());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
