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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;

class XAdESLevelBDetachedWithXmlPolicyWithTransformsTest extends AbstractXAdESTestSignature {

	private static final String SIGNATURE_POLICY_ID = "urn:sbr:signature-policy:xml:2.0";
	private static final String SIGNATURE_POLICY_URL = "http://www.nltaxonomie.nl/sbr/signature_policy_schema/v2.0/SBR-signature-policy-v2.0.xml";

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new FileDocument("src/test/resources/sample.xml");

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		
		DSSDocument signaturePolicy = new FileDocument(
				"src/test/resources/validation/dss2095/SBR-signature-policy-v2.0.xml");

		XmlPolicyWithTransforms xmlPolicyWithTransforms = new XmlPolicyWithTransforms();
		xmlPolicyWithTransforms.setId(SIGNATURE_POLICY_ID);
		xmlPolicyWithTransforms.setSpuri(SIGNATURE_POLICY_URL);
		xmlPolicyWithTransforms.setDigestAlgorithm(DigestAlgorithm.SHA256);
		
		// Prepare transformations in the proper order
		List<DSSTransform> policyTransforms = new ArrayList<>();
		DSSTransform canonicalization = new CanonicalizationTransform(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
		policyTransforms.add(canonicalization);
		DSSTransform subtractDigestFilter = new XPath2FilterTransform("/*/*[local-name()='SignPolicyDigest']", "subtract");
		policyTransforms.add(subtractDigestFilter);
		
		xmlPolicyWithTransforms.setTransforms(policyTransforms);

		byte[] binariesAfterTransforms = DSSXMLUtils.applyTransforms(signaturePolicy, policyTransforms);
		xmlPolicyWithTransforms.setDigestValue(DSSUtils.digest(DigestAlgorithm.SHA256, binariesAfterTransforms));

		signatureParameters.bLevel().setSignaturePolicy(xmlPolicyWithTransforms);

		service = new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();

		Map<String, DSSDocument> mapById = new HashMap<>();
		mapById.put("urn:sbr:signature-policy:xml:2.0",
				new FileDocument("src/test/resources/validation/dss2095/SBR-signature-policy-v2.0.xml"));
		signaturePolicyProvider.setSignaturePoliciesById(mapById);

		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		return validator;
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		Document doc = DomUtils.buildDOM(byteArray);

		NodeList signatures = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(doc);
		assertEquals(1, signatures.getLength());

		NodeList objectList = ((Element) signatures.item(0))
				.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Object");
		assertEquals(1, objectList.getLength());

		NodeList qualPropsList = ((Element) objectList.item(0))
				.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "QualifyingProperties");
		assertEquals(1, qualPropsList.getLength());

		NodeList signedPropsList = ((Element) qualPropsList.item(0))
				.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedProperties");
		assertEquals(1, signedPropsList.getLength());

		NodeList signedSigPropsList = ((Element) signedPropsList.item(0))
				.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignedSignatureProperties");
		assertEquals(1, signedSigPropsList.getLength());

		NodeList sigPolIdentifierList = ((Element) signedSigPropsList.item(0))
				.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignaturePolicyIdentifier");
		assertEquals(1, sigPolIdentifierList.getLength());

		NodeList sigPolIdList = ((Element) sigPolIdentifierList.item(0))
				.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "SignaturePolicyId");
		assertEquals(1, sigPolIdList.getLength());

		NodeList transformsList = ((Element) sigPolIdList.item(0))
				.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Transforms");
		assertEquals(1, transformsList.getLength());

		NodeList transformList = ((Element) sigPolIdList.item(0))
				.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Transform");
		assertEquals(2, transformList.getLength());
	}

	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		assertTrue(signature.isPolicyPresent());
		assertTrue(signature.isPolicyIdentified());
		assertTrue(signature.isPolicyDigestValid());
		assertTrue(signature.isPolicyDigestAlgorithmsEqual());

		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
		assertEquals(SIGNATURE_POLICY_URL, signature.getPolicyUrl());
		assertEquals(2, signature.getPolicyTransforms().size());

		assertNotNull(signature.getPolicyDigestAlgoAndValue());
		assertEquals(DigestAlgorithm.SHA256, signature.getPolicyDigestAlgoAndValue().getDigestMethod());
		assertTrue(Utils.isArrayNotEmpty(signature.getPolicyDigestAlgoAndValue().getDigestValue()));
	}

	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(documentToSign);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
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

}
