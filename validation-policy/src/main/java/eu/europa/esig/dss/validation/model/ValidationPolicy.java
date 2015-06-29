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
package eu.europa.esig.dss.validation.model;

import java.net.URL;

import org.w3c.dom.Document;

import eu.europa.esig.dss.XmlDom;

/**
 * In memory representation on the XML Validation Policy Constraint document and XSD
 */
public class ValidationPolicy {
	private Document document;
	private XmlDom xmlDom;
	private final URL sourceXSD;

	public ValidationPolicy(XmlDom xmlDom, URL sourceXSD, Document document) {
		this.xmlDom = xmlDom;
		this.document = document;
		this.sourceXSD = sourceXSD;
	}

	public Document getDocument() {
		return document;
	}

	public XmlDom getXmlDom() {
		return xmlDom;
	}

	public void setXmlDom(XmlDom xmlDom) {
		this.xmlDom = xmlDom;
	}

	public URL getSourceXSD() {
		return sourceXSD;
	}
}
