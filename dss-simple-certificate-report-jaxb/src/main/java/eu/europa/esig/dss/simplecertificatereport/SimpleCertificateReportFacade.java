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

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;

public class SimpleCertificateReportFacade extends AbstractJaxbFacade<XmlSimpleCertificateReport> {

	public static SimpleCertificateReportFacade newFacade() {
		return new SimpleCertificateReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return SimpleCertificateReportXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return SimpleCertificateReportXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlSimpleCertificateReport> wrap(XmlSimpleCertificateReport simpleCertificateReport) {
		return SimpleCertificateReportXmlDefiner.OBJECT_FACTORY.createSimpleCertificateReport(simpleCertificateReport);
	}

	public String generateHtmlReport(XmlSimpleCertificateReport simpleCertificateReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(simpleCertificateReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(XmlSimpleCertificateReport simpleCertificateReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleCertificateReport)), result);
	}

	public String generateHtmlReport(String marshalledSimpleCertificateReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledSimpleCertificateReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(String marshalledSimpleCertificateReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleCertificateReport)), result);
	}

}
