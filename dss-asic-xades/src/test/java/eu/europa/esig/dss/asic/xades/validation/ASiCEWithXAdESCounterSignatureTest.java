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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithXAdESCounterSignatureTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/container-with-counter-signature.asice");
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
			assertTrue(Utils.isCollectionNotEmpty(signatureScopes));
			
			boolean fullDocumentFound = false;
			for (XmlSignatureScope signatureScope : signatureScopes) {
				if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
					fullDocumentFound = true;
					if (signature.isCounterSignature()) {
						assertEquals("service-body.json", signatureScope.getName());
					} else {
						assertEquals("service-body-excl-debtor.json", signatureScope.getName());
					}
				}
			}
			assertTrue(fullDocumentFound);
		}
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		
		AdvancedSignature signature = signatures.iterator().next();
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatures.iterator().next());
		assertEquals(2, originalDocuments.size());

		List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
		assertEquals(1, counterSignatures.size());
		
		originalDocuments = validator.getOriginalDocuments(counterSignatures.iterator().next());
		assertEquals(6, originalDocuments.size());
	}

	@Override
	protected void checkStructureValidation(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertFalse(signatureWrapper.isStructuralValidationValid());
			assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getStructuralValidationMessages()));

			boolean notValidNameErrorFound = false;
			for (String error : signatureWrapper.getStructuralValidationMessages()) {
				if (error.contains("NCName")) {
					notValidNameErrorFound = true;
					break;
				}
			}
			assertTrue(notValidNameErrorFound);
		}
	}

	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		boolean signCertFound = false;
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			assertNotNull(certificateWrapper);
			assertNotNull(certificateWrapper.getId());
			assertNotNull(certificateWrapper.getCertificateDN());
			assertNotNull(certificateWrapper.getCertificateIssuerDN());
			assertNotNull(certificateWrapper.getNotAfter());
			assertNotNull(certificateWrapper.getNotBefore());
			assertTrue(Utils.isCollectionNotEmpty(certificateWrapper.getSources()));
			assertNotNull(certificateWrapper.getEntityKey());

			if (certificateWrapper.getSigningCertificate() != null) {
				assertNotNull(certificateWrapper.getIssuerEntityKey());
				assertFalse(certificateWrapper.isSelfSigned());
				assertTrue(certificateWrapper.isMatchingIssuerKey());
				assertFalse(certificateWrapper.isMatchingIssuerSubjectName());
				assertNotEquals(certificateWrapper.getEntityKey(), certificateWrapper.getIssuerEntityKey());
				signCertFound = true;
			}
		}
		assertTrue(signCertFound);
	}

	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
	}

}
