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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
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
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelTWithSignaturePolicyStoreTest extends AbstractXAdESTestSignature {

	private static final String HTTP_SPURI_TEST = "http://spuri.test";
	private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
	private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
	private static final String SIGNATURE_POLICY_DOCUMENTATION = "http://nowina.lu/signature-policy.pdf";
	private static final String OPTIONAL_ID = "mySignaturePolicyStore";

	private static final DSSDocument POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());

	private XAdESService service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		Policy signaturePolicy = new Policy();
		signaturePolicy.setId("urn:oid:" + SIGNATURE_POLICY_ID);
		signaturePolicy.setDescription(SIGNATURE_POLICY_DESCRIPTION);
		signaturePolicy.setDocumentationReferences(SIGNATURE_POLICY_DOCUMENTATION, Utils.EMPTY_STRING); // empty is permitted as URI

		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signaturePolicy.setDigestValue(DSSUtils.digest(DigestAlgorithm.SHA256, POLICY_CONTENT));
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

		service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Override
	protected DSSDocument sign() {
		DSSDocument signedDocument = super.sign();

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setId(OPTIONAL_ID);
		signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
		String[] documentationReferences = new String[] { SIGNATURE_POLICY_DOCUMENTATION };
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId("urn:oid:" + SIGNATURE_POLICY_ID);
		spDocSpec.setDescription(SIGNATURE_POLICY_DESCRIPTION);
		spDocSpec.setDocumentationReferences(documentationReferences);
		spDocSpec.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
		signaturePolicyStore.setSpDocSpecification(spDocSpec);
		DSSDocument signedDocumentWithSignaturePolicyStore = service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
		assertNotNull(signedDocumentWithSignaturePolicyStore);
		
		return signedDocumentWithSignaturePolicyStore;
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		
		String xmlContent = new String(byteArray);
		assertTrue(xmlContent.contains("description"));
		assertTrue(xmlContent.contains(":DocumentationReferences>"));
		assertTrue(xmlContent.contains(":DocumentationReference>"));
		assertTrue(xmlContent.contains(":SigPolicyQualifiers>"));
		assertTrue(xmlContent.contains(":SigPolicyQualifier>"));
		assertTrue(xmlContent.contains(HTTP_SPURI_TEST));
		
		assertTrue(xmlContent.contains(":SignaturePolicyStore"));
		assertTrue(xmlContent.contains(":SPDocSpecification"));
		assertTrue(xmlContent.contains(":SignaturePolicyDocument"));
		assertTrue(xmlContent.contains(OPTIONAL_ID));
		assertTrue(xmlContent.contains(ObjectIdentifierQualifier.OID_AS_URN.getValue()));
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		assertEquals(1, signatures.size());
		
		XAdESSignature xadesSignature = (XAdESSignature) signatures.get(0);
		SignaturePolicyStore extractedSPS = xadesSignature.getSignaturePolicyStore();
		assertNotNull(extractedSPS);
		assertEquals(OPTIONAL_ID, extractedSPS.getId());
		assertNotNull(extractedSPS.getSpDocSpecification());
		assertEquals(SIGNATURE_POLICY_ID, extractedSPS.getSpDocSpecification().getId());
		assertEquals(ObjectIdentifierQualifier.OID_AS_URN, extractedSPS.getSpDocSpecification().getQualifier());
		assertEquals(SIGNATURE_POLICY_DESCRIPTION, extractedSPS.getSpDocSpecification().getDescription());
		assertArrayEquals(new String[] { SIGNATURE_POLICY_DOCUMENTATION }, extractedSPS.getSpDocSpecification().getDocumentationReferences());
		assertArrayEquals(DSSUtils.toByteArray(POLICY_CONTENT), DSSUtils.toByteArray(extractedSPS.getSignaturePolicyContent()));
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isPolicyPresent());
		
		assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
		assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyDescription());
		assertEquals(SIGNATURE_POLICY_DOCUMENTATION, signature.getPolicyDocumentationReferences().get(0));
		assertEquals(Utils.EMPTY_STRING, signature.getPolicyDocumentationReferences().get(1));
		
		assertFalse(signature.isPolicyAsn1Processable());
		assertTrue(signature.isPolicyIdentified());
		assertTrue(signature.isPolicyDigestValid());
		assertTrue(signature.isPolicyDigestAlgorithmsEqual());
	}
	
	@Override
	protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyStore(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());
		assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyStoreDescription());
		assertEquals(1, signature.getPolicyStoreDocumentationReferences().size());
		assertEquals(SIGNATURE_POLICY_DOCUMENTATION, signature.getPolicyStoreDocumentationReferences().get(0));
		
		XmlDigestAlgoAndValue policyStoreDigestAlgoAndValue = signature.getPolicyStoreDigestAlgoAndValue();
		assertNotNull(policyStoreDigestAlgoAndValue);
		assertNotNull(signature.getPolicyStoreDigestAlgoAndValue().getDigestMethod());
		assertTrue(Utils.isArrayNotEmpty(policyStoreDigestAlgoAndValue.getDigestValue()));
		
		XmlDigestAlgoAndValue policyDigestAlgoAndValue = signature.getPolicyDigestAlgoAndValue();
		assertEquals(policyDigestAlgoAndValue.getDigestMethod(), policyStoreDigestAlgoAndValue.getDigestMethod());
		assertArrayEquals(policyDigestAlgoAndValue.getDigestValue(), policyStoreDigestAlgoAndValue.getDigestValue());
		
		assertArrayEquals(POLICY_CONTENT.getDigestValue(policyDigestAlgoAndValue.getDigestMethod()), policyDigestAlgoAndValue.getDigestValue());
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
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
