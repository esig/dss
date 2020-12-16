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
package eu.europa.esig.dss.simplereport;

import eu.europa.esig.dss.jaxb.AbstractJaxbFacade;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import org.xml.sax.SAXException;

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
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

/**
 * Contains methods to generate SimpleReport
 */
public class SimpleReportFacade extends AbstractJaxbFacade<XmlSimpleReport> {

	/**
	 * Instantiates a new {@code SimpleReportFacade}
	 *
	 * @return {@link SimpleReportFacade}
	 */
	public static SimpleReportFacade newFacade() {
		return new SimpleReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return SimpleReportXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return SimpleReportXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlSimpleReport> wrap(XmlSimpleReport simpleReport) {
		return SimpleReportXmlDefiner.OBJECT_FACTORY.createSimpleReport(simpleReport);
	}

	/**
	 * Generates a Bootstrap 4 Simple report
	 *
	 * @param simpleReport {@link XmlSimpleReport}
	 * @return {@link String}
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
	 */
	public String generateHtmlReport(XmlSimpleReport simpleReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(simpleReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a Bootstrap 4 Simple report
	 *
	 * @param simpleReport {@link XmlSimpleReport}
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
	 */
	public void generateHtmlReport(XmlSimpleReport simpleReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleReport)), result);
	}

	/**
	 * Generates a Bootstrap 4 Simple report
	 *
	 * @param marshalledSimpleReport {@link String} marshalled report
	 * @return {@link String}
	 * @throws IOException if IOException occurs
	 * @throws TransformerException if TransformerException occurs
	 */
	public String generateHtmlReport(String marshalledSimpleReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledSimpleReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a Bootstrap 4 Simple report
	 *
	 * @param marshalledSimpleReport {@link String} marshalled report
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 */
	public void generateHtmlReport(String marshalledSimpleReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleReport)), result);
	}

	/**
	 * Generates a Bootstrap 3 Simple report
	 *
	 * @param simpleReport {@link XmlSimpleReport}
	 * @return {@link String}
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
	 */
	public String generateHtmlBootstrap3Report(XmlSimpleReport simpleReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlBootstrap3Report(simpleReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a Bootstrap 3 Simple report
	 *
	 * @param simpleReport {@link XmlSimpleReport}
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
	 */
	public void generateHtmlBootstrap3Report(XmlSimpleReport simpleReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleReport)), result);
	}

	/**
	 * Generates a Bootstrap 3 Simple report
	 *
	 * @param marshalledSimpleReport {@link String} marshalled report
	 * @return {@link String}
	 * @throws IOException if IOException occurs
	 * @throws TransformerException if TransformerException occurs
	 */
	public String generateHtmlBootstrap3Report(String marshalledSimpleReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlBootstrap3Report(marshalledSimpleReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a Bootstrap 3 Simple report
	 *
	 * @param marshalledSimpleReport {@link String} marshalled report
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 */
	public void generateHtmlBootstrap3Report(String marshalledSimpleReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleReport)), result);
	}

	/**
	 * Generates a PDF Simple report
	 *
	 * @param simpleReport {@link XmlSimpleReport}
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
	 */
	public void generatePdfReport(XmlSimpleReport simpleReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleReport)), result);
	}

	/**
	 * Generates a PDF Simple report
	 *
	 * @param marshalledSimpleReport {@link String} marshalled report
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 */
	public void generatePdfReport(String marshalledSimpleReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleReport)), result);
	}

}
