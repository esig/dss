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
package eu.europa.ec.markt.dss.applet.util;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import java.io.*;
import java.net.URL;

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
		Transformer transformer = null;
		try {
			transformer = TransformerFactory.newInstance().newTransformer();
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
