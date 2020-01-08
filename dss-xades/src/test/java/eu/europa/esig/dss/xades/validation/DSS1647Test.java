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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1647Test {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss-1647_OJ_L_2018_109_FULL.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		//commonCertificateVerifier.setIncludeCertificateRevocationValues(true);
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertEquals(2, timestamps.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		timestamps = signature.getTimestampList();
		TimestampWrapper archiveTimestamp = timestamps.get(1);
		assertEquals(TimestampType.ARCHIVE_TIMESTAMP, archiveTimestamp.getType());
		assertEquals(4, archiveTimestamp.getTimestampedCertificateIds().size());
		assertEquals(3, archiveTimestamp.getTimestampedRevocationIds().size());
		assertEquals(1, archiveTimestamp.getTimestampedTimestampIds().size());
		
		List<String> timestampValidationDataCertificateIds = signature.getFoundCertificateIds(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
		assertEquals(1, timestampValidationDataCertificateIds.size());
		assertTrue(archiveTimestamp.getTimestampedCertificateIds().contains(timestampValidationDataCertificateIds.get(0)));
		
		List<String> certificateValueIds = signature.getFoundCertificateIds(CertificateOrigin.CERTIFICATE_VALUES);
		assertEquals(3, certificateValueIds.size());
		for (String certId : certificateValueIds) {
			assertTrue(archiveTimestamp.getTimestampedCertificateIds().contains(certId));
		}
		
		List<String> timestampValidationDataRevocationIds = signature.getRevocationIdsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
		assertEquals(1, timestampValidationDataRevocationIds.size());
		assertTrue(archiveTimestamp.getTimestampedRevocationIds().contains(timestampValidationDataRevocationIds.get(0)));
		
		List<String> crlRevocationValueIds = signature.getRevocationIdsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES);
		assertEquals(1, crlRevocationValueIds.size());
		assertTrue(archiveTimestamp.getTimestampedRevocationIds().contains(crlRevocationValueIds.get(0)));
		
		List<String> ocspRevocationValueIds = signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES);
		assertEquals(1, ocspRevocationValueIds.size());
		assertTrue(archiveTimestamp.getTimestampedRevocationIds().contains(ocspRevocationValueIds.get(0)));
	}

}
