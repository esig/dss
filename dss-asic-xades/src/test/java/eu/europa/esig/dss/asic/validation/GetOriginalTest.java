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
package eu.europa.esig.dss.asic.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class GetOriginalTest {

	private final List<DSSDocument> EXPECTED_MULTIFILES = Arrays.<DSSDocument> asList(
			new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT),
			new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));

	private final DSSDocument EXPECTED_ONEFILE = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);

	@Test
	public void testMultifilesASICSOneToMuchFile() {
		FileDocument signedDoc = new FileDocument("src/test/resources/validation/multifiles-too-much-files.asics");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(signedDoc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(2, signatures.size());

		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(advancedSignature.getId());
			assertEquals(2, originalDocuments.size());
			isFoundAllOriginals(originalDocuments);
		}
		
		Reports reports = sdv.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
		for (SignatureWrapper signature : signatureWrappers) {
			assertNotNull(signature);
			List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
			assertNotNull(signatureScopes);
			assertEquals(3, signatureScopes.size());
			int archivedFiles = 0;
			for (XmlSignatureScope signatureScope : signatureScopes) {
				if (SignatureScopeType.ARCHIVED.equals(signatureScope.getScope())) {
					archivedFiles++;
				}
			}
			assertEquals(2, archivedFiles);
		}
	}

	@Test
	public void testMultifilesASICEOneToMuchFile() {
		FileDocument signedDoc = new FileDocument("src/test/resources/validation/multifiles-too-much-files.asice");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(signedDoc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(2, signatures.size());

		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(advancedSignature.getId());
			assertEquals(2, originalDocuments.size());
			isFoundAllOriginals(originalDocuments);
		}
		
		Reports reports = sdv.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertNotNull(signature.getSignatureScopes());
		assertEquals(2, signature.getSignatureScopes().size());
	}

	private void isFoundAllOriginals(List<DSSDocument> retrievedDocuments) {
		for (DSSDocument dssDocument : EXPECTED_MULTIFILES) {
			String digestExpected = dssDocument.getDigest(DigestAlgorithm.SHA256);
			boolean found = false;
			for (DSSDocument retrieved : retrievedDocuments) {
				String digestRetrieved = retrieved.getDigest(DigestAlgorithm.SHA256);
				if (Utils.areStringsEqual(digestExpected, digestRetrieved)) {
					found = true;
				}
			}
			assertTrue(found);
		}
	}

	@Test
	public void testOnefileASICSOneToMuchFile() {
		FileDocument signedDoc = new FileDocument("src/test/resources/validation/onefile-too-much-files.asics");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(signedDoc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(1, signatures.size());

		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(advancedSignature.getId());
			assertEquals(1, originalDocuments.size());
			assertEquals(EXPECTED_ONEFILE.getDigest(DigestAlgorithm.SHA256), originalDocuments.get(0).getDigest(DigestAlgorithm.SHA256));
		}
		
		Reports reports = sdv.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertNotNull(signature.getSignatureScopes());
		assertEquals(1, signature.getSignatureScopes().size());
	}

	@Test
	public void testOnefileASICEOneToMuchFile() {

		FileDocument signedDoc = new FileDocument("src/test/resources/validation/onefile-too-much-files.asice");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(signedDoc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(1, signatures.size());

		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(advancedSignature.getId());
			assertEquals(1, originalDocuments.size());
			assertEquals(EXPECTED_ONEFILE.getDigest(DigestAlgorithm.SHA256), originalDocuments.get(0).getDigest(DigestAlgorithm.SHA256));
		}
	}

	@Test
	public void testMultifilesASICSWrongFile() {
		FileDocument signedDoc = new FileDocument("src/test/resources/validation/multifiles-wrong-file.asics");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(signedDoc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(2, signatures.size());

		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(advancedSignature.getId());
			assertTrue(Utils.isCollectionEmpty(originalDocuments));
		}
	}

	@Test
	public void testMultifilesASICEWrongFile() {
		FileDocument signedDoc = new FileDocument("src/test/resources/validation/multifiles-wrong-file.asice");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(signedDoc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(2, signatures.size());

		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(advancedSignature.getId());
			assertTrue(Utils.isCollectionEmpty(originalDocuments));
		}
	}

	@Test
	public void testOnefileASICSWrongFile() {
		FileDocument signedDoc = new FileDocument("src/test/resources/validation/onefile-wrong-file.asics");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(signedDoc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(1, signatures.size());

		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(advancedSignature.getId());
			assertTrue(Utils.isCollectionEmpty(originalDocuments));
		}
	}

	@Test
	public void testOnefileASICEWrongFile() {
		FileDocument signedDoc = new FileDocument("src/test/resources/validation/onefile-wrong-file.asice");

		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(signedDoc);
		sdv.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(1, signatures.size());

		for (AdvancedSignature advancedSignature : signatures) {
			List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(advancedSignature.getId());
			assertTrue(Utils.isCollectionEmpty(originalDocuments));
		}
	}

}
