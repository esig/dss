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

public class XPathTransform extends ComplexTransform {
	
	protected static final String DS_XPATH = "ds:XPath";
	
	protected final String xPathExpression;
	
	protected XPathTransform(String algorithm, String xPathExpression) {
		super(algorithm);
		Objects.requireNonNull(xPathExpression, "xPathExpression cannot be null!");
		this.xPathExpression = xPathExpression;
	}

	public XPathTransform(String xPathExpression) {
		this(Transforms.TRANSFORM_XPATH, xPathExpression);
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transform = super.createTransform(document, parentNode);
		return DomUtils.addTextElement(document, transform, namespace, DS_XPATH, xPathExpression);
	}

}
