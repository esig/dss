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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESWithPolicyValidationTest extends AbstractXAdESTestValidation {

	private static final String POLICY_ID = "1.3.6.1.4.1.10015.1000.3.2.1";
	private static final String POLICY_URL = "http://spuri.test";

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/valid-xades.xml");
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertEquals(POLICY_ID, signature.getPolicyId());
		assertEquals(POLICY_URL, signature.getPolicyUrl());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		// do nothing
	}

	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		boolean signCertFound = false;
		boolean caSelfSignedFound = false;
		boolean caWronglySelfSignedFound = false;
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

				if (!certificateWrapper.isSelfSigned()) {
					if (certificateWrapper.getIssuerEntityKey().equals(certificateWrapper.getSigningCertificate().getEntityKey())) {
						assertTrue(certificateWrapper.isMatchingIssuerKey());
						assertTrue(certificateWrapper.isMatchingIssuerSubjectName());
						signCertFound = true;
					} else {
						assertTrue(certificateWrapper.isMatchingIssuerKey());
						assertFalse(certificateWrapper.isMatchingIssuerSubjectName());
						caWronglySelfSignedFound = true;
					}
				}

			} else if (certificateWrapper.isSelfSigned()) {
				assertNotNull(certificateWrapper.getIssuerEntityKey());
				assertEquals(certificateWrapper.getEntityKey(), certificateWrapper.getIssuerEntityKey());
				assertTrue(certificateWrapper.isMatchingIssuerKey());
				assertTrue(certificateWrapper.isMatchingIssuerSubjectName());
				caSelfSignedFound = true;
			}
		}
		assertTrue(signCertFound);
		assertTrue(caSelfSignedFound);
		assertTrue(caWronglySelfSignedFound);
	}

}
