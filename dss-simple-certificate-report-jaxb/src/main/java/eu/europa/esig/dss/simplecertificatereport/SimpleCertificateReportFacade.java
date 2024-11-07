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
package eu.europa.esig.dss.simplecertificatereport;

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.util.JAXBSource;
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
 * Contains methods to generate Certificate SimpleReport
 */
public class SimpleCertificateReportFacade extends AbstractJaxbFacade<XmlSimpleCertificateReport> {

	/**
	 * Default constructor
	 */
	protected SimpleCertificateReportFacade() {
		// empty
	}

	/**
	 * Instantiates a new {@code SimpleCertificateReportFacade}
	 *
	 * @return {@link SimpleCertificateReportFacade}
	 */
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

    /**
     * Generates a Bootstrap 4 Simple Certificate report
	 *
	 * @param simpleCertificateReport {@link XmlSimpleCertificateReport}
	 * @return {@link String}
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
     */
	public String generateHtmlReport(XmlSimpleCertificateReport simpleCertificateReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(simpleCertificateReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a Bootstrap 4 Simple Certificate report
	 *
	 * @param simpleCertificateReport {@link XmlSimpleCertificateReport}
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
	 */
	public void generateHtmlReport(XmlSimpleCertificateReport simpleCertificateReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleCertificateReport)), result);
	}

	/**
	 * Generates a Bootstrap 4 Simple Certificate report
	 *
	 * @param marshalledSimpleCertificateReport {@link String} marshalled report
	 * @return {@link String}
	 * @throws IOException if IOException occurs
	 * @throws TransformerException if TransformerException occurs
	 */
	public String generateHtmlReport(String marshalledSimpleCertificateReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledSimpleCertificateReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a Bootstrap 4 Simple Certificate report
	 *
	 * @param marshalledSimpleCertificateReport {@link String} marshalled report
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 */
	public void generateHtmlReport(String marshalledSimpleCertificateReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleCertificateReport)), result);
	}
	
    /**
     * Generates a PDF Detailed report
	 *
	 * @param simpleCertificateReport {@link XmlSimpleCertificateReport}
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
     */
	public void generatePdfReport(XmlSimpleCertificateReport simpleCertificateReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleCertificateReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleCertificateReport)), result);
	}

	/**
	 * Generates a PDF Detailed report
	 *
	 * @param marshalledSimpleCertificateReport {@link String} marshalled report
	 * @param result {@link Result} to write the report into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 */
	public void generatePdfReport(String marshalledSimpleCertificateReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleCertificateReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleCertificateReport)), result);
	}

}
