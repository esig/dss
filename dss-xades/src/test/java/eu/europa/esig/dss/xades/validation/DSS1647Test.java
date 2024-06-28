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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

class DSS1647Test extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-1647_OJ_L_2018_109_FULL.xml");
	}
	
	@Override
	protected void checkTokens(DiagnosticData diagnosticData) {
		super.checkTokens(diagnosticData);
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertEquals(2, timestamps.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		timestamps = signature.getTimestampList();
		TimestampWrapper archiveTimestamp = timestamps.get(1);
		assertEquals(TimestampType.ARCHIVE_TIMESTAMP, archiveTimestamp.getType());
		assertEquals(5, archiveTimestamp.getTimestampedCertificates().size());
		assertEquals(2, archiveTimestamp.getTimestampedRevocations().size());
		assertEquals(1, archiveTimestamp.getTimestampedOrphanRevocations().size());
		assertEquals(1, archiveTimestamp.getTimestampedTimestamps().size());
		
		List<RelatedCertificateWrapper> timestampValidationDataCertificates = signature.foundCertificates()
				.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
		assertEquals(1, timestampValidationDataCertificates.size());
		assertTrue(archiveTimestamp.getTimestampedCertificates().stream().map(CertificateWrapper::getId)
				.collect(Collectors.toList()).contains(timestampValidationDataCertificates.get(0).getId()));
		
		List<RelatedCertificateWrapper> certificateValues = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
		assertEquals(3, certificateValues.size());
		for (RelatedCertificateWrapper cert : certificateValues) {
			assertTrue(archiveTimestamp.getTimestampedCertificates().stream().map(CertificateWrapper::getId)
					.collect(Collectors.toList()).contains(cert.getId()));
		}
		
		List<RelatedRevocationWrapper> timestampValidationDataRevocations = signature.foundRevocations()
				.getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
		assertEquals(0, timestampValidationDataRevocations.size());

		List<OrphanRevocationWrapper> timestampOrphanRevocations = signature.foundRevocations()
				.getOrphanRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
		assertEquals(1, timestampOrphanRevocations.size());
		assertTrue(archiveTimestamp.getTimestampedOrphanRevocations().stream().map(OrphanTokenWrapper::getId)
				.collect(Collectors.toList()).contains(timestampOrphanRevocations.get(0).getId()));
		
		List<RelatedRevocationWrapper> crlRevocationValues = signature.foundRevocations()
				.getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.REVOCATION_VALUES);
		assertEquals(1, crlRevocationValues.size());
		assertTrue(archiveTimestamp.getTimestampedRevocations().stream().map(RevocationWrapper::getId)
				.collect(Collectors.toList()).contains(crlRevocationValues.get(0).getId()));
		
		List<RelatedRevocationWrapper> ocspRevocationValues = signature.foundRevocations()
				.getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.REVOCATION_VALUES);
		assertEquals(1, ocspRevocationValues.size());
		assertTrue(archiveTimestamp.getTimestampedRevocations().stream().map(RevocationWrapper::getId)
				.collect(Collectors.toList()).contains(ocspRevocationValues.get(0).getId()));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		// has no LTA profile, because the chain is not trusted in offline
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		// do nothing
	}

}
