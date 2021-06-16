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
package eu.europa.esig.dss.asic.xades.signature.asics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.validation.AbstractASiCWithXAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;

public class ASiCSXAdESMultipleSignatureWithPolicyStoreTest extends AbstractASiCWithXAdESTestValidation {

	private static final String SIGNATURE_POLICY_ID = "urn:sbr:signature-policy";
	private static final DSSDocument POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());

	private ASiCWithXAdESService service;
	private DSSDocument documentToSign;

	private String signingAlias = GOOD_USER;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");
		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	private ASiCWithXAdESSignatureParameters initParameters() {
		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		Policy policy = new Policy();
		policy.setId(SIGNATURE_POLICY_ID);
		policy.setDigestAlgorithm(DigestAlgorithm.SHA256);
		policy.setDigestValue(Utils.fromBase64(POLICY_CONTENT.getDigest(DigestAlgorithm.SHA256)));
		signatureParameters.bLevel().setSignaturePolicy(policy);

		return signatureParameters;
	}

	@Override
	protected DSSDocument getSignedDocument() {
		DSSDocument signedDocument = sign(documentToSign, initParameters());
		signingAlias = RSA_SHA3_USER;
		DSSDocument doubleSignedDocument = sign(signedDocument, initParameters());

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId(SIGNATURE_POLICY_ID);
		signaturePolicyStore.setSpDocSpecification(spDocSpec);

		return service.addSignaturePolicyStore(doubleSignedDocument, signaturePolicyStore);
	}

	@Override
	protected SignaturePolicyProvider getSignaturePolicyProvider() {
		return null;
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);

		assertEquals(2, signatures.size());
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertEquals(SignatureLevel.XAdES_BASELINE_LTA, signature.getSignatureFormat());
		}
	}

	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isPolicyIdentified());
			assertTrue(signature.isPolicyPresent());
			assertTrue(signature.isPolicyDigestValid());
			assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
			assertTrue(signature.isPolicyDigestAlgorithmsEqual());
		}
	}

	@Override
	protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyStore(diagnosticData);

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isPolicyStorePresent());
			assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());
			assertNotNull(signature.getPolicyStoreDigestAlgoAndValue());
			assertNotNull(signature.getPolicyStoreDigestAlgoAndValue().getDigestMethod());
			assertTrue(Utils.isArrayNotEmpty(signature.getPolicyStoreDigestAlgoAndValue().getDigestValue()));
		}
	}

	private DSSDocument sign(DSSDocument documentToSign, ASiCWithXAdESSignatureParameters signatureParameters) {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				signatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

}
