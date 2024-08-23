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
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithXAdESDetachedCounterSignatureTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/detached-counter-signature.asice");
	}

	@Override
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		super.checkMessageDigestAlgorithm(diagnosticData);

		boolean detachedCounterSignatureFound = false;
		boolean counterSignedSignatureValueFound = false;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
				if (DigestMatcherType.COUNTER_SIGNATURE.equals(digestMatcher.getType())) {
					detachedCounterSignatureFound = true;
				} else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE.equals(digestMatcher.getType())) {
					counterSignedSignatureValueFound = true;
				}
			}
		}
		assertTrue(detachedCounterSignatureFound);
		assertFalse(counterSignedSignatureValueFound);
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
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// skip check (custom type)
	}

	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
	}

}
