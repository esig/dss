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
package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1794Test {

	@Test
	public void ADBERevocationCRLTest() throws Exception {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/adbe_crl_signed.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports validateDocument = validator.validateDocument();
		
		DiagnosticData diagnosticData = validateDocument.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<String> revocationIdsByOrigin = signature.getRevocationIdsByOrigin(RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
		assertNotNull(revocationIdsByOrigin);
		assertEquals(1, revocationIdsByOrigin.size());
		
//		validateDocument.print();
	}
	
	@Test
	public void ADBERevocationOCSPTest() throws Exception {
		DSSDocument dssDocument = new InMemoryDocument(
				getClass().getResourceAsStream("/validation/adbe_ocsp_signed.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		
		Reports validateDocument = validator.validateDocument();
		
		DiagnosticData diagnosticData = validateDocument.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<String> revocationIdsByOrigin = signature.getRevocationIdsByOrigin(RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
		assertNotNull(revocationIdsByOrigin);
		assertEquals(1, revocationIdsByOrigin.size());
		
//		validateDocument.print();
	}
}
