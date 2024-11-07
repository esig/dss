/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation.dss2011;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

class XAdESDetachedWithTransformTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss2011/xades-detached-with-transform.xml");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Collections.singletonList(new FileDocument("src/test/resources/sample-c14n.xml"));
	}

	@Override
	protected void checkDigestMatchers(DiagnosticData diagnosticData) {
		super.checkDigestMatchers(diagnosticData);

		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalSignerDocuments.size());
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		boolean referenceDigestMatcherFound = false;
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
				assertFalse(Arrays.equals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue(), digestMatcher.getDigestValue()));
				referenceDigestMatcherFound = true;
			}
		}
		assertTrue(referenceDigestMatcherFound);
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertNotNull(xmlSignatureScope.getSignerData());
		assertNotNull(xmlSignatureScope.getName());
		assertNotNull(xmlSignatureScope.getDescription());
		assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
		assertEquals(1, xmlSignatureScope.getTransformations().size());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(1, originalDocuments.size());
	}

}
