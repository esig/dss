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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class XAdES132OnlyTest {

	@Test
	public void test() {

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAIASource(null);
		FileDocument xmlDocument = new FileDocument("src/test/resources/signature-pool/signedXmlXadesB.xml");

		// tag::demo[]
		XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(xmlDocument);
		xmlDocumentValidator.setCertificateVerifier(certificateVerifier);

		// Restrict the current XMLDocumentValidator to XAdES 1.3.2 (and 1.4.1 for
		// archival timestamps)
		List<XAdESPaths> xadesPathsHolders = xmlDocumentValidator.getXAdESPathsHolder();
		xadesPathsHolders.clear();
		xadesPathsHolders.add(new XAdES132Paths());

		Reports reports = xmlDocumentValidator.validateDocument();
		// end::demo[]

		assertNotNull(reports);

	}

}
