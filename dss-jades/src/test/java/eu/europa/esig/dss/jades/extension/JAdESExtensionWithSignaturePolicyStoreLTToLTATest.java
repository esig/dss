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
package eu.europa.esig.dss.jades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class JAdESExtensionWithSignaturePolicyStoreLTToLTATest extends AbstractJAdESTestExtension {

	private static final String HTTP_SPURI_TEST = "http://spuri.test";
	private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
	private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
	private static final DSSDocument SIGNATURE_POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());
	private static final String[] DOCUMENTATION_REFERENCES = new String[] { "http://docref.com/ref1",
			"http://docref.com/ref2" };

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.JAdES_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.JAdES_BASELINE_LTA;
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = super.getSignatureParameters();

		Policy signaturePolicy = new Policy();
		signaturePolicy.setId("urn:oid:" + SIGNATURE_POLICY_ID);
		signaturePolicy.setDescription(SIGNATURE_POLICY_DESCRIPTION);
		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signaturePolicy.setDigestValue(DSSUtils.digest(DigestAlgorithm.SHA256, SIGNATURE_POLICY_CONTENT));
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);

		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		return signatureParameters;
	}

	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {
		DSSDocument signedDocument = super.getSignedDocument(doc);

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setSignaturePolicyContent(SIGNATURE_POLICY_CONTENT);
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId("urn:oid:" + SIGNATURE_POLICY_ID);
		spDocSpec.setDescription(SIGNATURE_POLICY_DESCRIPTION);
		spDocSpec.setDocumentationReferences(DOCUMENTATION_REFERENCES);
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
		assertEquals(2, signature.getPolicyStoreDocumentationReferences().size());
		assertEquals(DOCUMENTATION_REFERENCES[0], signature.getPolicyStoreDocumentationReferences().get(0));
		assertEquals(DOCUMENTATION_REFERENCES[1], signature.getPolicyStoreDocumentationReferences().get(1));

		XmlDigestAlgoAndValue policyStoreDigestAlgoAndValue = signature.getPolicyStoreDigestAlgoAndValue();
		assertNotNull(policyStoreDigestAlgoAndValue);
		assertNotNull(policyStoreDigestAlgoAndValue.getDigestMethod());
		assertTrue(Utils.isArrayNotEmpty(policyStoreDigestAlgoAndValue.getDigestValue()));
	}

}
