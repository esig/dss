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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESLevelBWithSignaturePolicyWithUriTest extends AbstractCAdESTestSignature {

	private static final String HTTP_SPURI_TEST = "http://spuri.test";
	private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";

	private static final DSSDocument POLICY_CONTENT = new FileDocument("src/test/resources/validation/signature-policy.der");

	private CAdESService service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello world".getBytes());

		Policy signaturePolicy = new Policy();
		signaturePolicy.setId(SIGNATURE_POLICY_ID);

		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signaturePolicy.setDigestValue(Utils.fromBase64("UB1ptLcfxuVzI8LHQTGpyMYkCb43i6eI3CiFVWEbnlg="));
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		service = new CAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Override
	protected DSSDocument sign() {
		DSSDocument signedDocument = super.sign();

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId(HTTP_SPURI_TEST);
		signaturePolicyStore.setSpDocSpecification(spDocSpec);
		DSSDocument signedDocumentWithSignaturePolicyStore = service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
		assertNotNull(signedDocumentWithSignaturePolicyStore);
		
		return signedDocumentWithSignaturePolicyStore;
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		assertEquals(1, signatures.size());
		
		CAdESSignature cadesSignature = (CAdESSignature) signatures.get(0);
		SignaturePolicyStore extractedSPS = cadesSignature.getSignaturePolicyStore();
		assertNotNull(extractedSPS);
		assertNotNull(extractedSPS.getSpDocSpecification());
		assertEquals(HTTP_SPURI_TEST, extractedSPS.getSpDocSpecification().getId());
		assertArrayEquals(DSSUtils.toByteArray(POLICY_CONTENT), DSSUtils.toByteArray(extractedSPS.getSignaturePolicyContent()));
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isPolicyPresent());
		
		assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
		
		assertTrue(signature.isPolicyAsn1Processable());
		assertTrue(signature.isPolicyIdentified());
		assertTrue(signature.isPolicyStatus());
		assertTrue(signature.isPolicyDigestAlgorithmsEqual());
	}
	
	@Override
	protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyStore(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(HTTP_SPURI_TEST, signature.getPolicyStoreId());
		
		assertNotNull(signature.getPolicyStoreDigestAlgoAndValue());
		assertNotNull(signature.getPolicyStoreDigestAlgoAndValue().getDigestMethod());
		assertTrue(Utils.isArrayNotEmpty(signature.getPolicyStoreDigestAlgoAndValue().getDigestValue()));
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
