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
package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

class DSS2123Test extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-2123.asice"));
	}
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		
		boolean revocationWithOtherIssuerFound = false;
		
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			CertificateWrapper signingCertificate = certificateWrapper.getSigningCertificate();
			if (signingCertificate == null) {
				continue;
			}
			
			List<CertificateRevocationWrapper> certificateRevocationData = certificateWrapper.getCertificateRevocationData();
			if (Utils.isCollectionNotEmpty(certificateRevocationData)) {
				for (CertificateRevocationWrapper certificateRevocationWrapper : certificateRevocationData) {
					if (RevocationType.OCSP.equals(certificateRevocationWrapper.getRevocationType())) {
						CertificateWrapper ocspSignCert = certificateRevocationWrapper.getSigningCertificate();
						assertNotNull(ocspSignCert);
						if (!signingCertificate.getId().equals(ocspSignCert.getId())) {
							revocationWithOtherIssuerFound = true;
							assertNotEquals(certificateWrapper.getEncryptionAlgorithm(), certificateRevocationWrapper.getEncryptionAlgorithm());
						}
					}
				}
			}
		}
		
		assertTrue(revocationWithOtherIssuerFound);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);

		assertEquals(SignatureLevel.XAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

}
