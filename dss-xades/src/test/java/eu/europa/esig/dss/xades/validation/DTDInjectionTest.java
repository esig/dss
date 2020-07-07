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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;

import javax.xml.parsers.ParserConfigurationException;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * Unit test added to fix issue : https://esig-dss.atlassian.net/browse/DSS-678
 */
public class DTDInjectionTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/xades-with-dtd-injection.xml"));
	}
	
	@Override
	@Test
	public void validate() {
		try {
			DomUtils.disableFeature("http://apache.org/xml/features/disallow-doctype-decl");
			super.validate();
			DomUtils.enableFeature("http://apache.org/xml/features/disallow-doctype-decl");
		} catch (ParserConfigurationException e) {
			fail(e);
		}
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// do nothing
	}

	@Test
	public void test() {
		FileDocument fileDocument = new FileDocument(
				new File("src/test/resources/validation/xades-with-dtd-injection.xml"));
		Exception exception = assertThrows(DSSException.class,
				() -> SignedDocumentValidator.fromDocument(fileDocument));
		assertEquals("Unable to parse content (XML expected)", exception.getMessage());
	}

}
