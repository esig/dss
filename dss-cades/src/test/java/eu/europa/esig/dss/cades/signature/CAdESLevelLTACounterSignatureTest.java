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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelLTACounterSignatureTest extends AbstractCAdESCounterSignatureTest {

	private CAdESService service;
	private DSSDocument documentToSign;

	private CAdESSignatureParameters signatureParameters;
	private CAdESCounterSignatureParameters counterSignatureParameters;
	private Date signingDate;

	@BeforeEach
	void init() throws Exception {
		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new InMemoryDocument("Hello World".getBytes());
		signingDate = new Date();
		
		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		
		counterSignatureParameters = new CAdESCounterSignatureParameters();
		counterSignatureParameters.bLevel().setSigningDate(signingDate);
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		counterSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
		return counterSignatureParameters;
	}
	
	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);
		
		assertEquals(2, diagnosticData.getSignatureIdList().size());
		for (String signatureId : diagnosticData.getSignatureIdList()) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
			if (signatureWrapper.isCounterSignature()) {
				assertEquals(SignatureLevel.CAdES_BASELINE_B, diagnosticData.getSignatureFormat(signatureId));
			} else {
				assertEquals(SignatureLevel.CAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(signatureId));
			}
		}
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isCounterSignature());
		
		FoundRevocationsProxy foundRevocations = signature.foundRevocations();
		assertEquals(2, foundRevocations.getRelatedRevocationData().size());
		assertEquals(1, foundRevocations.getRelatedRevocationsByType(RevocationType.CRL).size());
		assertEquals(1, foundRevocations.getRelatedRevocationsByType(RevocationType.OCSP).size());
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		boolean arcTstFound = false;
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				arcTstFound = true;
			}
		}

		assertTrue(arcTstFound);
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CounterSignatureService<CAdESCounterSignatureParameters> getCounterSignatureService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	@Test
	void ltaLevelCounterSignatureTest() {
		counterSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		Exception exception = assertThrows(UnsupportedOperationException.class, () -> signAndVerify());
		assertEquals("A counter signature with a level 'CAdES-BASELINE-LTA' is not supported! "
				+ "Please, use CAdES-BASELINE-B", exception.getMessage());
	}

}
