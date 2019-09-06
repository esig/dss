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



import java.io.File;
import javax.xml.parsers.ParserConfigurationException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * Unit test added to fix issue : https://esig-dss.atlassian.net/browse/DSS-678
 */
public class DTDInjectionTest {

	@Test
	public void test() {
		Exception exception = assertThrows(DSSException.class, () -> {
			SignedDocumentValidator validator = SignedDocumentValidator
					.fromDocument(new FileDocument(new File("src/test/resources/validation/xades-with-dtd-injection.xml")));
			validator.setCertificateVerifier(new CommonCertificateVerifier());
			validator.validateDocument();
		});
		assertEquals("Document format not recognized/handled", exception.getMessage());
	}

	@Test
	public void testSecurityDisabled() throws ParserConfigurationException {
		DomUtils.disableFeature("http://apache.org/xml/features/disallow-doctype-decl");

		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xades-with-dtd-injection.xml")));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DomUtils.enableFeature("http://apache.org/xml/features/disallow-doctype-decl");
	}

}
