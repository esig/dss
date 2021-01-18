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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.jaxb.AbstractJaxbFacade;
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

public class DiagnosticDataFacade extends AbstractJaxbFacade<XmlDiagnosticData> {

	public static DiagnosticDataFacade newFacade() {
		return new DiagnosticDataFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return DiagnosticDataXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return DiagnosticDataXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlDiagnosticData> wrap(XmlDiagnosticData diagnosticDataJaxb) {
		return DiagnosticDataXmlDefiner.OBJECT_FACTORY.createDiagnosticData(diagnosticDataJaxb);
	}

	/**
	 * Generates a SVG representation of the diagnostic data
	 *
	 * @param diagnosticDataJaxb {@link XmlDiagnosticData}
	 * @return {@link String}
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
	 */
	public String generateSVG(XmlDiagnosticData diagnosticDataJaxb) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateSVG(diagnosticDataJaxb, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}
	
	/**
     * Generates a SVG representation of the diagnostic data
	 *
	 * @param diagnosticDataJaxb {@link XmlDiagnosticData}
	 * @param result {@link Result} the result's output
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 * @throws JAXBException if an JAXBException occurs
     */
	public void generateSVG(XmlDiagnosticData diagnosticDataJaxb, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = DiagnosticDataXmlDefiner.getSvgTemplates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(diagnosticDataJaxb)), result);
	}

	/**
	 * Generates a SVG representation of the diagnostic data
	 *
	 * @param marshalledDiagnosticData {@link String} marshalled diagnostic data
	 * @return {@link String}
	 * @throws IOException if IOException occurs
	 * @throws TransformerException if TransformerException occurs
	 */
	public String generateSVG(String marshalledDiagnosticData) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateSVG(marshalledDiagnosticData, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	/**
	 * Generates a SVG representation of the diagnostic data
	 *
	 * @param marshalledDiagnosticData {@link String} marshalled diagnostic data
	 * @param result {@link Result} to write the SVG into
	 * @throws IOException if an IOException occurs
	 * @throws TransformerException if an TransformerException occurs
	 */
	public void generateSVG(String marshalledDiagnosticData, Result result) throws IOException, TransformerException {
		Transformer transformer = DiagnosticDataXmlDefiner.getSvgTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledDiagnosticData)), result);
	}

}
