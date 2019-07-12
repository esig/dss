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
package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1420 {

	@Test
	public void testSHA3_0() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1420/PAdES-BpB-att-SHA256-SHA3_256withRSA.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		PAdESSignature pades = (PAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = pades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA256, messageDigestAlgorithms.iterator().next());
		assertNotNull(pades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, pades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_256, pades.getDigestAlgorithm());
		assertNull(pades.getMaskGenerationFunction());

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testSHA3_1() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1420/PAdES-BpB-att-SHA256-SHA3_224withRSA.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		PAdESSignature pades = (PAdESSignature) signatures.get(0);

		Set<DigestAlgorithm> messageDigestAlgorithms = pades.getMessageDigestAlgorithms();
		assertEquals(1, signatures.size());
		assertEquals(DigestAlgorithm.SHA256, messageDigestAlgorithms.iterator().next());
		assertNotNull(pades.getMessageDigestValue());

		assertEquals(EncryptionAlgorithm.RSA, pades.getEncryptionAlgorithm());
		assertEquals(DigestAlgorithm.SHA3_224, pades.getDigestAlgorithm());
		assertNull(pades.getMaskGenerationFunction());

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
