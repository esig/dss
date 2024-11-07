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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESTripleLTATest extends AbstractCAdESTestSignature {
	
	private DSSDocument documentToSign;
	private CAdESSignatureParameters parameters;
	private CAdESService service;
	
	@BeforeEach
	void init() {
		documentToSign = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8));
		
		parameters = new CAdESSignatureParameters();
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

        service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Override
	public void signAndVerify() {
		// do nothing
	}

	@Test
	void test() throws Exception {
		DSSDocument signed = sign();
		// signed.save("target/signed.pksc7");
		Reports reports = verify(signed);
		
		service.setTspSource(getAlternateGoodTsa());

		DSSDocument doubleLtaDoc = service.extendDocument(signed, parameters);
		// doubleLtaDoc.save("target/doubleLTA.pksc7");
		reports = verify(doubleLtaDoc);

		DiagnosticData diagnosticDataOne = reports.getDiagnosticData();
		List<String> doubleSignatureRootSignedDataCertificateIds = getRootSignedDataCertificateIds(diagnosticDataOne);

		DSSDocument tripleLtaDoc = service.extendDocument(doubleLtaDoc, parameters);
		// tripleLtaDoc.save("target/tripleLTA.pksc7");
		reports = verify(tripleLtaDoc);

		DiagnosticData diagnosticDataTwo = reports.getDiagnosticData();

		List<String> tripleSignatureRootSignedDataCertificateIds = getRootSignedDataCertificateIds(diagnosticDataTwo);
		assertTrue(tripleSignatureRootSignedDataCertificateIds.size() > doubleSignatureRootSignedDataCertificateIds.size());
		for (String certId : doubleSignatureRootSignedDataCertificateIds) {
			assertTrue(tripleSignatureRootSignedDataCertificateIds.contains(certId));
		}
		
		compareTimestamps(diagnosticDataOne, diagnosticDataTwo);

		assertEquals(4, diagnosticDataTwo.getTimestampIdList(diagnosticDataTwo.getFirstSignatureId()).size());
		TimestampWrapper lastArchiveTimestamp = null;
		int archiveTstCounter = 0;
		for (TimestampWrapper timestampWrapper : diagnosticDataTwo.getTimestampList()) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				if (lastArchiveTimestamp != null) {
					assertTrue(lastArchiveTimestamp.getTimestampedCertificates().size() <= timestampWrapper.getTimestampedCertificates().size());
				}
				for (CertificateWrapper certificateWrapper : timestampWrapper.getTimestampedCertificates()) {
					assertTrue(tripleSignatureRootSignedDataCertificateIds.contains(certificateWrapper.getId()));
				}
				lastArchiveTimestamp = timestampWrapper;
				++archiveTstCounter;
			}
		}
		assertNotNull(lastArchiveTimestamp);
		assertEquals(3, archiveTstCounter);

	}
	
	private List<String> getRootSignedDataCertificateIds(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<RelatedCertificateWrapper> signedDataCertificates = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA);
		return signedDataCertificates.stream().map(c -> c.getId()).collect(Collectors.toList());
	}
	
	private void compareTimestamps(DiagnosticData diagnosticDataOne, DiagnosticData diagnosticDataTwo) {
		List<TimestampWrapper> timestampListOne = diagnosticDataOne.getTimestampList();
		List<TimestampWrapper> timestampListTwo = diagnosticDataTwo.getTimestampList();
		for (int i = 0; i < timestampListOne.size(); i++) {
			TimestampWrapper timestampOne = timestampListOne.get(i);
			TimestampWrapper timestampTwo = timestampListTwo.get(i);
			assertEquals(timestampOne.foundCertificates().getRelatedCertificates().size(), 
					timestampTwo.foundCertificates().getRelatedCertificates().size());
			assertEquals(timestampOne.foundCertificates().getOrphanCertificates().size(), 
					timestampTwo.foundCertificates().getOrphanCertificates().size());
			assertEquals(timestampOne.foundRevocations().getRelatedRevocationData().size(), 
					timestampTwo.foundRevocations().getRelatedRevocationData().size());
			assertEquals(timestampOne.foundRevocations().getOrphanRevocationData().size(), 
					timestampTwo.foundRevocations().getOrphanRevocationData().size());
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return parameters;
	}

}
