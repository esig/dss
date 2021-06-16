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
package eu.europa.esig.dss.asic.cades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.AbstractASiCWithCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;

public class ASiCECAdESMultipleSignatureWithPolicyStoreTest extends AbstractASiCWithCAdESTestValidation {

	private static final String HTTP_SPURI_TEST = "http://spuri.test";
	private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";

	private static final DSSDocument POLICY_CONTENT = new FileDocument("src/test/resources/signature-policy.der");

	private ASiCWithCAdESService service;
	private DSSDocument documentToSign;

	private String signingAlias = GOOD_USER;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");
		service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	private ASiCWithCAdESSignatureParameters initParameters() {
		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		Policy signaturePolicy = new Policy();
		signaturePolicy.setId(SIGNATURE_POLICY_ID);

		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signaturePolicy.setDigestValue(Utils.fromBase64("UB1ptLcfxuVzI8LHQTGpyMYkCb43i6eI3CiFVWEbnlg="));
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);

		return signatureParameters;
	}

	@Override
	protected DSSDocument getSignedDocument() {
		ASiCWithCAdESSignatureParameters parameters = initParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		DSSDocument signedDocument = sign(documentToSign, parameters);
		signingAlias = RSA_SHA3_USER;
		DSSDocument doubleSignedDocument = sign(signedDocument, initParameters());

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId(HTTP_SPURI_TEST);
		signaturePolicyStore.setSpDocSpecification(spDocSpec);

		Exception exception = assertThrows(DSSException.class,
				() -> service.addSignaturePolicyStore(doubleSignedDocument, signaturePolicyStore));
		assertTrue(exception.getMessage().contains("The counter signature is not possible!"));

		return service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
	}

	@Override
	protected SignaturePolicyProvider getSignaturePolicyProvider() {
		return null;
	}

	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);

		assertEquals(1, signatures.size());
	}

	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertEquals(SignatureLevel.CAdES_BASELINE_T, signature.getSignatureFormat());
		}
	}

	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isPolicyIdentified());
			assertTrue(signature.isPolicyPresent());
			assertTrue(signature.isPolicyDigestValid());

			assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
			assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());

			assertTrue(signature.isPolicyAsn1Processable());
			assertTrue(signature.isPolicyIdentified());
			assertTrue(signature.isPolicyDigestValid());
			assertTrue(signature.isPolicyDigestAlgorithmsEqual());
		}
	}

	@Override
	protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyStore(diagnosticData);

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertTrue(signature.isPolicyStorePresent());
			assertEquals(HTTP_SPURI_TEST, signature.getPolicyStoreId());
			assertNotNull(signature.getPolicyStoreDigestAlgoAndValue());
			assertNotNull(signature.getPolicyStoreDigestAlgoAndValue().getDigestMethod());
			assertTrue(Utils.isArrayNotEmpty(signature.getPolicyStoreDigestAlgoAndValue().getDigestValue()));
		}
	}

	private DSSDocument sign(DSSDocument documentToSign, ASiCWithCAdESSignatureParameters signatureParameters) {
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
