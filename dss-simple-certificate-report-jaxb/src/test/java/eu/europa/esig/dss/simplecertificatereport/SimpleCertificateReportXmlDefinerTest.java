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
package eu.europa.esig.dss.simplecertificatereport;

import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;


class SimpleCertificateReportXmlDefinerTest {

	@Test
	void getJAXBContext() throws JAXBException {
		assertNotNull(SimpleCertificateReportXmlDefiner.getJAXBContext());
		assertNotNull(SimpleCertificateReportXmlDefiner.getJAXBContext());
	}

	@Test
	void getSchema() throws SAXException, IOException {
		assertNotNull(SimpleCertificateReportXmlDefiner.getSchema());
		assertNotNull(SimpleCertificateReportXmlDefiner.getSchema());
	}

	@Test
	void getHtmlBootstrap4Templates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = SimpleCertificateReportXmlDefiner.getHtmlBootstrap4Templates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(SimpleCertificateReportXmlDefiner.getHtmlBootstrap4Templates());
	}

}
