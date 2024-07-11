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
package eu.europa.esig.dss.asic.xades.extension.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.extension.AbstractASiCWithXAdESTestExtension;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEXAdESExtensionWithSignaturePolicyStoreBToLTATest extends AbstractASiCWithXAdESTestExtension {

	private static final String HTTP_SPURI_TEST = "http://spuri.test";
	private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
	private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
	private static final String SIGNATURE_POLICY_DOCUMENTATION = "http://nowina.lu/signature-policy.pdf";
	private static final String OPTIONAL_ID = "mySignaturePolicyStore";

	private static final DSSDocument POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LTA;
	}

	@Override
	protected ASiCContainerType getContainerType() {
		return ASiCContainerType.ASiC_E;
	}
	
	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		ASiCWithXAdESSignatureParameters signatureParameters = super.getSignatureParameters();

		Policy signaturePolicy = new Policy();
		signaturePolicy.setId("urn:oid:" + SIGNATURE_POLICY_ID);
		signaturePolicy.setDescription(SIGNATURE_POLICY_DESCRIPTION);
		signaturePolicy.setDocumentationReferences(SIGNATURE_POLICY_DOCUMENTATION, Utils.EMPTY_STRING); // empty is permitted as URI

		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signaturePolicy.setDigestValue(DSSUtils.digest(DigestAlgorithm.SHA256, POLICY_CONTENT));
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);

		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		return signatureParameters;
	}
	
	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {
		DSSDocument signedDocument = super.getSignedDocument(doc);

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

		return getSignatureServiceToSign().addSignaturePolicyStore(signedDocument, signaturePolicyStore);
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

		assertArrayEquals(POLICY_CONTENT.getDigestValue(policyDigestAlgoAndValue.getDigestMethod()),
				policyDigestAlgoAndValue.getDigestValue());
	}

}
