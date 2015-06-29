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
package eu.europa.esig.dss.applet.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.model.ValidationPolicy;

/**
 *
 */
public class ValidationPolicyDao {

	private static final Logger logger = LoggerFactory.getLogger(ValidationPolicyDao.class);

	private URL xmlUrl;
	private URL xsdUrl;

	public URL getXmlUrl() {
		return xmlUrl;
	}

	public URL getXsdUrl() {
		return xsdUrl;
	}

	public ValidationPolicy load(URL url, URL xsdUrl) {
		try {
			this.xmlUrl = url;
			this.xsdUrl = xsdUrl;
			return load(url.openStream(), xsdUrl.openStream());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public ValidationPolicy load(InputStream inputStream, InputStream xsdInputStream) throws DSSException {
		//To clone inputStream
		byte[] fileInputStream = cloneFileInputStream(inputStream);
		InputStream inputStreamClone2 = new ByteArrayInputStream(fileInputStream);

		byte[] fileInputStreamXsd = cloneFileInputStream(xsdInputStream);
		InputStream xsdStream1 = new ByteArrayInputStream(fileInputStreamXsd);
		InputSource sourceentree = new InputSource(xsdStream1);

		final Document document = DSSXMLUtils.buildDOM(inputStreamClone2);

		//Clean XML
		XPath xp = XPathFactory.newInstance().newXPath();
		NodeList nl = null;
		try {
			nl = (NodeList) xp.evaluate("//text()[normalize-space(.)='']", document, XPathConstants.NODESET);
		} catch (XPathExpressionException e) {
			logger.error(e.getMessage(), e);
		}
		for (int i = 0; i < nl.getLength(); ++i) {
			Node node = nl.item(i);
			node.getParentNode().removeChild(node);
		}
		document.normalizeDocument();
		document.normalize();

		final XmlDom xmlDom = new XmlDom(document);
		final ValidationPolicy validationPolicy = new ValidationPolicy(xmlDom, xsdUrl, document);

		return validationPolicy;
	}

	private byte[] cloneFileInputStream(InputStream inputStream) {
		//To clone inputStream
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buf = new byte[1024];
		int n = 0;
		try {
			while ((n = inputStream.read(buf)) >= 0) {
				baos.write(buf, 0, n);
			}
		} catch (IOException e) {
			logger.error(e.getMessage(), e);
		}
		byte[] content = baos.toByteArray();
		return baos.toByteArray();
	}

	public void save(ValidationPolicy validationPolicy, OutputStream outputStream) {
		try {
			TransformerFactory transformerFactory = DSSXMLUtils.getSecureTransformerFactory();
			Transformer transformer = transformerFactory.newTransformer();
			Result output = new StreamResult(outputStream);
			Source input = new DOMSource(validationPolicy.getDocument());

			transformer.transform(input, output);
		} catch (TransformerConfigurationException e) {
			logger.error(e.getMessage(), e);
		} catch (TransformerException e) {
			logger.error(e.getMessage(), e);
		}

	}
}
