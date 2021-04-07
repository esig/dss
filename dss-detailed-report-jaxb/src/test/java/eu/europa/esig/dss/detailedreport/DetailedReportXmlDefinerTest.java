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
package eu.europa.esig.dss.detailedreport;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;


public class DetailedReportXmlDefinerTest {

	@Test
	public void getJAXBContext() throws SAXException, JAXBException {
		assertNotNull(DetailedReportXmlDefiner.getJAXBContext());
		assertNotNull(DetailedReportXmlDefiner.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException, IOException {
		assertNotNull(DetailedReportXmlDefiner.getSchema());
		assertNotNull(DetailedReportXmlDefiner.getSchema());
	}

	@Test
	public void getHtmlBootstrap4Templates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = DetailedReportXmlDefiner.getHtmlBootstrap4Templates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(DetailedReportXmlDefiner.getHtmlBootstrap4Templates());
	}

	@Test
	public void getPdfTemplates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = DetailedReportXmlDefiner.getPdfTemplates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(DetailedReportXmlDefiner.getPdfTemplates());
	}

}
