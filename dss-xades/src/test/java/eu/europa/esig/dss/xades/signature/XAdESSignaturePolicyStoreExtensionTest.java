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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESSignaturePolicyStoreExtensionTest extends AbstractXAdESTestValidation {

	private static final String SIGNATURE_POLICY_ID = "urn:sbr:signature-policy:xml:2.0";
	private static final DSSDocument POLICY_CONTENT = new FileDocument("src/test/resources/validation/dss2095/SBR-signature-policy-v2.0.xml");

	private XAdESService service;
	private DSSDocument signedDocument;

	@BeforeEach
	public void init() throws Exception {
		signedDocument = new FileDocument("src/test/resources/validation/dss2095/sigPolicyWithTransforms.xml");
		service = new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected DSSDocument getSignedDocument() {
		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId(SIGNATURE_POLICY_ID);
		signaturePolicyStore.setSpDocSpecification(spDocSpec);
		
		DSSDocument signedDocumentWithSignaturePolicyStore = service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
		assertNotNull(signedDocumentWithSignaturePolicyStore);
		
		return signedDocumentWithSignaturePolicyStore;
	}
	
	@Override
	protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyStore(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());
		
		XmlDigestAlgoAndValue policyStoreDigestAlgoAndValue = signature.getPolicyStoreDigestAlgoAndValue();
		assertNotNull(policyStoreDigestAlgoAndValue);
		assertNotNull(policyStoreDigestAlgoAndValue.getDigestMethod());
		assertTrue(Utils.isArrayNotEmpty(policyStoreDigestAlgoAndValue.getDigestValue()));
		
		XmlDigestAlgoAndValue policyDigestAlgoAndValue = signature.getPolicyDigestAlgoAndValue();
		assertEquals(policyDigestAlgoAndValue.getDigestMethod(), policyStoreDigestAlgoAndValue.getDigestMethod());
		assertArrayEquals(policyDigestAlgoAndValue.getDigestValue(), policyStoreDigestAlgoAndValue.getDigestValue());
		
		// transforms are applied
		assertFalse(Arrays.equals(POLICY_CONTENT.getDigestValue(policyDigestAlgoAndValue.getDigestMethod()),
				policyDigestAlgoAndValue.getDigestValue()));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		// skip, the signature is invalid
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		// skip
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getOriginalSignerDocuments().size());
	}
	
	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		assertNull(signersDocument);
	}

}
