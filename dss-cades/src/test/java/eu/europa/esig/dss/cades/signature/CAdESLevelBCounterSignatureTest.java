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
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelBCounterSignatureTest extends AbstractCAdESCounterSignatureTest {

	private CAdESService service;
	private DSSDocument documentToSign;

	private Date signingDate;

	@BeforeEach
	void init() throws Exception {
		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new InMemoryDocument("Hello World".getBytes(), "test.text", MimeTypeEnum.TEXT);
		signingDate = new Date();
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		return signatureParameters;
	}

	@Override
	protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
		CAdESCounterSignatureParameters signatureParameters = new CAdESCounterSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setLocality("Kehlen");
		signatureParameters.bLevel().setSignerLocation(signerLocation);
		signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(CommitmentTypeEnum.ProofOfCreation));
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		assertEquals(1, signatures.size());

		CAdESSignature cadesSignature = (CAdESSignature) signatures.get(0);
		Set<DigestAlgorithm> messageDigestAlgorithms = cadesSignature.getMessageDigestAlgorithms();
		assertEquals(2, messageDigestAlgorithms.size());

		boolean sha256Found = false;
		boolean sha512Found = false;
		for (DigestAlgorithm digestAlgorithm : messageDigestAlgorithms) {
			if (DigestAlgorithm.SHA256.equals(digestAlgorithm)) {
				sha256Found = true;
			} else if (DigestAlgorithm.SHA512.equals(digestAlgorithm)) {
				sha512Found = true;
			}
		}
		assertTrue(sha256Found);
		assertTrue(sha512Found);
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		boolean counterSignatureFound = false;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.isCounterSignature()) {
				List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
				assertEquals(1, signatureScopes.size());
				
				XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
				assertEquals(SignatureScopeType.COUNTER_SIGNATURE, xmlSignatureScope.getScope());
				assertEquals(signatureWrapper.getParent().getId(), xmlSignatureScope.getName());
				
				counterSignatureFound = true;
			}
		}
		assertTrue(counterSignatureFound);
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		boolean masterSigFound = false;
		boolean counterSigFound = false;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.isCounterSignature()) {
				assertNull(signatureWrapper.getMimeType());
				counterSigFound = true;
			} else {
				assertNotNull(signatureWrapper.getMimeType());
				assertEquals(MimeTypeEnum.TEXT, MimeType.fromMimeTypeString(signatureWrapper.getMimeType()));
				masterSigFound = true;
			}
		}
		assertTrue(masterSigFound);
		assertTrue(counterSigFound);
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

}
