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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XMLCertificateWrappingTest extends PKIFactoryAccess {
	
	@Test
	public void certificateSourcesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/Signature-X-HU_POL-3.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper certificate : certificates) {
			assertNotNull(certificate.getSources());
			assertNotEquals(0, certificate.getSources().size());
			assertFalse(certificate.getSources().contains(CertificateSourceType.UNKNOWN));
		}
	}
	
	@Test
	public void certificateMultipleSourcesTest() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/Signature-X-CZ_SEF-5.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		int certsFromTimestamp = 0;
		for (CertificateWrapper certificate : certificates) {
			List<CertificateSourceType> certSources = certificate.getSources();
			assertNotNull(certSources);
			assertNotEquals(0, certSources.size());
			if (certSources.contains(CertificateSourceType.TIMESTAMP)) {
				assertEquals(2, certSources.size());
				assertTrue(certSources.contains(CertificateSourceType.SIGNATURE));
				certsFromTimestamp++;
			}
			assertFalse(certificate.getSources().contains(CertificateSourceType.UNKNOWN));
			assertNotNull(certificate.getDigestAlgoAndValue());
			assertEquals(DigestAlgorithm.SHA256, certificate.getDigestAlgoAndValue().getDigestMethod());
		}
		assertEquals(1, certsFromTimestamp);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
