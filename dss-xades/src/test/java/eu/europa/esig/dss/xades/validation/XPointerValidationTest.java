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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

public class XPointerValidationTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/10963_signed.xml");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(3, digestMatchers.size());
		boolean keyInfoDigestMatcherFound = false;
		boolean xPointerDigestMatcherFound = false;
		XmlDigestMatcher xPointerDigestMatcher = null;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.KEY_INFO.equals(digestMatcher.getType())) {
				keyInfoDigestMatcherFound = true;
			} else if (DigestMatcherType.XPOINTER.equals(digestMatcher.getType())) {
				xPointerDigestMatcherFound = true;
				xPointerDigestMatcher = digestMatcher;
			}
		}
		assertTrue(keyInfoDigestMatcherFound);
		assertTrue(xPointerDigestMatcherFound);
		
		assertNotNull(xPointerDigestMatcher);
		assertNotNull(xPointerDigestMatcher.getDigestMethod());
		assertNotNull(xPointerDigestMatcher.getDigestValue());
		assertTrue(xPointerDigestMatcher.isDataFound());
		assertTrue(xPointerDigestMatcher.isDataIntact());
		
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		assertEquals(SignatureScopeType.PARTIAL, xmlSignatureScope.getScope());
		assertEquals("XPointer query to element with Id 'SignedObject-1516693867353'",
				xmlSignatureScope.getDescription());
		XmlSignerData xPointerSignerData = xmlSignatureScope.getSignerData();
		
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalSignerDocuments.size());
		
		SignerDataWrapper xmlSignerData = originalSignerDocuments.get(0);
		assertNotNull(xmlSignerData.getDigestAlgoAndValue());
		
		assertEquals(xPointerSignerData.getId(), xmlSignerData.getId());
		
		assertEquals(xPointerDigestMatcher.getDigestMethod(), xmlSignerData.getDigestAlgoAndValue().getDigestMethod());
		assertEquals(Utils.toBase64(xPointerDigestMatcher.getDigestValue()), Utils.toBase64(xmlSignerData.getDigestAlgoAndValue().getDigestValue()));
        assertArrayEquals(xPointerDigestMatcher.getDigestValue(), xmlSignerData.getDigestAlgoAndValue().getDigestValue());
	}

}
