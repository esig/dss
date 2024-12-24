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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

class XAdESSignedSingleSignaturePropertyTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/signature_property_signed.xml"));
	}

	@Override
	protected void checkDigestMatchers(DiagnosticData diagnosticData) {
		super.checkDigestMatchers(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(3, digestMatchers.size());
		
		boolean signedPropertiesFound = false;
		boolean signaturePropertiesFound = false;
		boolean referenceFound = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			switch (digestMatcher.getType()) {
				case SIGNED_PROPERTIES:
					signedPropertiesFound = true;
					break;
				case SIGNATURE_PROPERTIES:
					signaturePropertiesFound = true;
					break;
				case REFERENCE:
					referenceFound = true;
					break;
				default:
					fail("Unexpected DigestMatcherType: " + digestMatcher.getType());
			}
		}
		assertTrue(signedPropertiesFound);
		assertTrue(signaturePropertiesFound);
		assertTrue(referenceFound);
	}

}
