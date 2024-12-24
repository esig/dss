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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

class DSS1562Test extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/xades-detached-with-object-type-ref.xml");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		DSSDocument detachedContent = new FileDocument("src/test/resources/sample.png");
		return Arrays.asList(detachedContent);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		assertNotNull(signature.getDigestMatchers());
		assertEquals(2, signature.getDigestMatchers().size());
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			assertNotNull(digestMatcher.getType());
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
		
		assertFalse(signature.isSignatureIntact());
		assertFalse(signature.isSignatureValid());
		assertFalse(signature.isBLevelTechnicallyValid());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertFalse(timestampWrapper.isMessageImprintDataIntact());
				assertFalse(timestampWrapper.isMessageImprintDataIntact());
			}
		}
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionEmpty(originalDocuments));
	}
	
}
