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
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelLTATest extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World".getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		assertEquals(2, diagnosticData.getTimestampList().size());
		boolean sigTstFound = false;
		boolean arcTstFound = false;

		String timestampId = diagnosticData.getSignatures().get(0).getTimestampList().get(0).getId();
		for (TimestampWrapper wrapper : diagnosticData.getTimestampList(diagnosticData.getFirstSignatureId())) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(wrapper.getType())) {
				assertEquals(0, wrapper.getTimestampScopes().size());
				assertEquals(1, wrapper.getTimestampedSignedData().size());
				sigTstFound = true;

			} else
				if (TimestampType.ARCHIVE_TIMESTAMP.equals(wrapper.getType())) {
				boolean coverPreviousTsp = false;
				List<TimestampWrapper> timestampedTimestamps = wrapper.getTimestampedTimestamps();
				for (TimestampWrapper timestamp : timestampedTimestamps) {
					if (timestampId.equals(timestamp.getId())) {
						coverPreviousTsp = true;
					}
				}
				assertTrue(coverPreviousTsp);

				assertEquals(1, wrapper.getTimestampScopes().size());
				assertEquals(1, wrapper.getTimestampedSignedData().size());
				arcTstFound = true;
			}
			
			List<SignatureWrapper> timestampedSignatures = wrapper.getTimestampedSignatures();
			boolean found = false;
			for (SignatureWrapper signatureWrapper : timestampedSignatures) {
				if (diagnosticData.getFirstSignatureId().equals(signatureWrapper.getId())) {
					found = true;
				}
			}
			assertTrue(found);
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper wrapper: allSignatures) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
		}

		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper wrapper: usedCertificates) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
		}

		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper wrapper : allRevocationData) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
		}

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper wrapper : timestampList) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
		}
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
