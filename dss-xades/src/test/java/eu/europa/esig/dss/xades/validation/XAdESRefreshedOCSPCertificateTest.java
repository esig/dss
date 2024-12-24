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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

class XAdESRefreshedOCSPCertificateTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/xades-with-equivalent-certs.xml");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
		validator.setCertificateVerifier(certificateVerifier);
		return validator;
	}
	
	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		super.checkCertificates(diagnosticData);
		
		boolean equivalentCertsFound = false;
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			List<CertificateWrapper> equivalentCertificates = diagnosticData.getEquivalentCertificates(certificateWrapper);
			if (Utils.isCollectionNotEmpty(equivalentCertificates)) {
				equivalentCertsFound = true;
				for (CertificateWrapper equivalentCert : equivalentCertificates) {
					assertEquals(certificateWrapper.getEntityKey(), equivalentCert.getEntityKey());
					assertEquals(certificateWrapper.getCertificateDN(), equivalentCert.getCertificateDN());
					assertEquals(certificateWrapper.getCertificateIssuerDN(), equivalentCert.getCertificateIssuerDN());
					assertNotEquals(certificateWrapper.getNotBefore(), equivalentCert.getNotBefore());
					assertNotEquals(certificateWrapper.getNotAfter(), equivalentCert.getNotAfter());
					assertNotEquals(certificateWrapper.getDigestAlgorithm(), equivalentCert.getDigestAlgorithm());
				}
			}
		}
		assertTrue(equivalentCertsFound);
	}

	@Override
	protected void checkStructureValidation(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureWrapper.isStructuralValidationValid());
		assertEquals(1, signatureWrapper.getStructuralValidationMessages().size());
		assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains(
				"\"http://uri.etsi.org/01903/v1.3.2#\":StateOrProvince"));
	}

}
