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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xml.common.DocumentBuilderFactoryBuilder;
import eu.europa.esig.dss.xml.common.XmlDefinerUtils;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit test added to fix issue : https://esig-dss.atlassian.net/browse/DSS-678
 */
class DTDInjectionTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/xades-with-dtd-injection.xml"));
	}
	
	@Override
	@Test
	public void validate() {
		try {
			XmlDefinerUtils.getInstance().setDocumentBuilderFactoryBuilder(
					DocumentBuilderFactoryBuilder.getSecureDocumentBuilderFactoryBuilder()
							.disableFeature("http://apache.org/xml/features/disallow-doctype-decl"));
			super.validate();
		} finally {
			XmlDefinerUtils.getInstance().setDocumentBuilderFactoryBuilder(
					DocumentBuilderFactoryBuilder.getSecureDocumentBuilderFactoryBuilder()
							.enableFeature("http://apache.org/xml/features/disallow-doctype-decl"));
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
	void test() {
		FileDocument fileDocument = new FileDocument(
				new File("src/test/resources/validation/xades-with-dtd-injection.xml"));
		Exception exception = assertThrows(IllegalInputException.class,
				() -> SignedDocumentValidator.fromDocument(fileDocument));
		assertTrue(exception.getMessage().contains("An XML file is expected : Unable to parse content (XML expected)"));
	}

}
