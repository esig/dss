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
package eu.europa.esig.dss.xades.validation.dss1770;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

class DSS1770NullUriWithMultipleDetachedTest extends AbstractXAdESTestValidation {
			
	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss1770/dss1770refUriRemoved.xml");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		List<DSSDocument> detachedDocuments = new ArrayList<>();
		detachedDocuments.add(new FileDocument("src/test/resources/sample.png"));
		detachedDocuments.add(new FileDocument("src/test/resources/sample.xml"));
		return detachedDocuments;
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		assertEquals(2, signatureScopes.size());
		
		int fullScopeCounter = 0;
		int partialScopeCounter = 0;
		for (XmlSignatureScope signatureScope : signatureScopes) {
			if (SignatureScopeType.FULL.equals(signatureScope.getScope())) {
				fullScopeCounter++;
			} else if (SignatureScopeType.PARTIAL.equals(signatureScope.getScope())) {
				partialScopeCounter++;
			}
		}
		assertEquals(0, fullScopeCounter);
		assertEquals(2, partialScopeCounter);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureWrapper = signatures.get(0);
		
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		assertEquals(4, digestMatchers.size());
		boolean refRootFound = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if ("REF-ROOT".equals(digestMatcher.getName())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				refRootFound = true;
			}
		}
		assertTrue(refRootFound);
	}

}
