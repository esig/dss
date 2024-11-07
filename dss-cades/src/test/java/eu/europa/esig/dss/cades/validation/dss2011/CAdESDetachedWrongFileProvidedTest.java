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
package eu.europa.esig.dss.cades.validation.dss2011;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESDetachedWrongFileProvidedTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-2011/cades-detached.pkcs7");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(new InMemoryDocument("Bye World".getBytes()));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		boolean referenceDigestMatcherFound = false;
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType())) {
				assertTrue(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				assertEquals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod(), digestMatcher.getDigestMethod());
                assertArrayEquals(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue(), digestMatcher.getDigestValue());
				referenceDigestMatcherFound = true;
			}
		}
		assertTrue(referenceDigestMatcherFound);
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);

		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertEquals(1, originalSignerDocuments.size());
		
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(1, originalDocuments.size());
		assertFalse(Arrays.equals(originalDocuments.get(0).getDigestValue(originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestMethod()),
				originalSignerDocuments.get(0).getDigestAlgoAndValue().getDigestValue()));
	}

}
