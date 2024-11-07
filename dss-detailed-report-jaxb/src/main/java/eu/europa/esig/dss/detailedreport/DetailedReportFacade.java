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
package eu.europa.esig.dss.detailedreport;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
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
 * Contains methods for DetailedReport generation
 */
public class DetailedReportFacade extends AbstractJaxbFacade<XmlDetailedReport> {

	/**
	 * Default constructor
	 */
	protected DetailedReportFacade() {
		// empty
	}

	/**
	 * Creates a new {@code DetailedReportFacade}
	 *
	 * @return {@link DetailedReportFacade}
	 */
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
     * Generates a Bootstrap 4 Detailed report
	 *
	 * @param detailedReport {@link XmlDetailedReport} JAXB report
	 * @return {@link String} Bootstrap 4 HTML report
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
     */
	public String generateHtmlReport(XmlDetailedReport detailedReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(detailedReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a Bootstrap 4 Detailed report and writes to {@code result}
	 *
	 * @param detailedReport {@link XmlDetailedReport} JAXB report
	 * @param result {@link Result} to embed the report to
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
	 */
	public void generateHtmlReport(XmlDetailedReport detailedReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = DetailedReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(detailedReport)), result);
	}

	/**
	 * Generates a Bootstrap 4 Detailed report from a string
	 *
	 * @param marshalledDetailedReport {@link String} the marshalled detailed report
	 * @return {@link String} Bootstrap 4 HTML report
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 */
	public String generateHtmlReport(String marshalledDetailedReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledDetailedReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a Bootstrap 4 Detailed report from a string and writes to {@code result}
	 *
	 * @param marshalledDetailedReport {@link String} the marshalled detailed report
	 * @param result {@link Result} to embed the report to
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 */
	public void generateHtmlReport(String marshalledDetailedReport, Result result) throws IOException, TransformerException {
		Transformer transformer = DetailedReportXmlDefiner.getHtmlBootstrap4Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledDetailedReport)), result);
	}

	/**
	 * Generates a PDF Detailed report
	 *
	 * @param detailedReport {@link XmlDetailedReport} JAXB report
	 * @param result {@link Result} to embed the report to
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if a Transformer Exception occurs
	 * @throws JAXBException if a JAXB Exception occurs
	 */
	public void generatePdfReport(XmlDetailedReport detailedReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = DetailedReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(detailedReport)), result);
	}

	/**
	 * Generates a PDF Detailed report
	 *
	 * @param marshalledDetailedReport {@link String} the marshalled detailed report
	 * @param result {@link Result} to embed the report to
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if a Transformer Exception occurs
	 */
	public void generatePdfReport(String marshalledDetailedReport, Result result) throws IOException, TransformerException {
		Transformer transformer = DetailedReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledDetailedReport)), result);
	}

}
