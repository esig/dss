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

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.util.JAXBSource;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;

public class DetailedReportFacade extends AbstractJaxbFacade<XmlDetailedReport> {

	public static DetailedReportFacade newFacade() {
		return new DetailedReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return DetailedReportXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return DetailedReportXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlDetailedReport> wrap(XmlDetailedReport detailedReport) {
		return DetailedReportXmlDefiner.OBJECT_FACTORY.createDetailedReport(detailedReport);
	}

    /**
     * Generates a Boostrap 4 Detailed report
     */
	public String generateHtmlReport(XmlDetailedReport detailedReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(detailedReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(XmlDetailedReport detailedReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = DetailedReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(detailedReport)), result);
	}

	public String generateHtmlReport(String marshalledDetailedReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledDetailedReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(String marshalledDetailedReport, Result result) throws IOException, TransformerException {
		Transformer transformer = DetailedReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledDetailedReport)), result);
	}

    /**
     * Generates a Boostrap 3 Detailed report
     */
	public String generateHtmlBootstrap3Report(XmlDetailedReport detailedReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlBootstrap3Report(detailedReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlBootstrap3Report(XmlDetailedReport detailedReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = DetailedReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(detailedReport)), result);
	}

	public String generateHtmlBootstrap3Report(String marshalledDetailedReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlBootstrap3Report(marshalledDetailedReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlBootstrap3Report(String marshalledDetailedReport, Result result) throws IOException, TransformerException {
		Transformer transformer = DetailedReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledDetailedReport)), result);
	}
	
    /**
     * Generates a PDF Detailed report
     */
	public void generatePdfReport(XmlDetailedReport detailedReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = DetailedReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(detailedReport)), result);
	}

	public void generatePdfReport(String marshalledDetailedReport, Result result) throws IOException, TransformerException {
		Transformer transformer = DetailedReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledDetailedReport)), result);
	}

}
