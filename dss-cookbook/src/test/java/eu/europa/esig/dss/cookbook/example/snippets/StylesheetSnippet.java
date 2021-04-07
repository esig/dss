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
package eu.europa.esig.dss.cookbook.example.snippets;

import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;

import javax.xml.transform.Transformer;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportXmlDefiner;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;

public class StylesheetSnippet {
	
	@SuppressWarnings("unused")
	public void demo() {
		
		XmlSimpleReport xmlSimpleReport = new XmlSimpleReport();
		try {
			// tag::demo[]
			String bootstrap4Report = SimpleReportFacade.newFacade().generateHtmlReport(xmlSimpleReport);
			// end::demo[]
		} catch (Exception e) {
			// catch the exception
		}
		
		String simpleReport = null;
		// tag::custom[]
		try (Writer writer = new StringWriter()) {
			Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
			// specify custom parameters if needed
			transformer.transform(new StreamSource(new StringReader(simpleReport)), new StreamResult(writer));
			String bootstrap4Report = writer.toString();
		} 
		// end::custom[]
		catch (Exception e) {
			// catch the exception
		}
	}

}
