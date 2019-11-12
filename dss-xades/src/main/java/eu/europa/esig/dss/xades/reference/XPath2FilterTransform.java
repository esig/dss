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
package eu.europa.esig.dss.xades.reference;

import java.util.Objects;

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;

public class XPath2FilterTransform extends XPathTransform {
	
	private static final String FILTER_ATTRIBUTE = "Filter";
	private static final String XPATH2_FILTER_NAMESPACE = "http://www.w3.org/2002/06/xmldsig-filter2";
	
	private final String filter;

	public XPath2FilterTransform(String xPathExpression, String filter) {
		super(Transforms.TRANSFORM_XPATH2FILTER, xPathExpression);
		Objects.requireNonNull(filter, "filter cannot be null!");
		this.filter = filter;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transform = DomUtils.addElement(document, parentNode, namespace, DS_TRANSFORM);
		transform.setAttribute(ALGORITHM_ATTRIBUTE_NAME, algorithm);
		// XPath element must have a specific namespace
		Element xPathElement = DomUtils.addTextElement(document, transform, XPATH2_FILTER_NAMESPACE, DS_XPATH, xPathExpression);
		xPathElement.setPrefix("dsig-xpath");
		xPathElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:dsig-xpath", XPATH2_FILTER_NAMESPACE);
		xPathElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", namespace);
		xPathElement.setAttribute(FILTER_ATTRIBUTE, filter);
		return xPathElement;
	}

}
