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
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;

public class XPathTransform extends ComplexTransform {
	
	protected final String xPathExpression;

	public XPathTransform(String xPathExpression) {
		this(XAdESNamespaces.XMLDSIG, Transforms.TRANSFORM_XPATH, xPathExpression);
	}
	
	public XPathTransform(DSSNamespace xmlDSigNamespace, String xPathExpression) {
		this(xmlDSigNamespace, Transforms.TRANSFORM_XPATH, xPathExpression);
	}
	
	protected XPathTransform(DSSNamespace xmlDSigNamespace, String algorithm, String xPathExpression) {
		super(xmlDSigNamespace, algorithm);
		Objects.requireNonNull(xPathExpression, "xPathExpression cannot be null!");
		this.xPathExpression = xPathExpression;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transform = super.createTransform(document, parentNode);
		return DomUtils.addTextElement(document, transform, namespace, XMLDSigElement.XPATH, xPathExpression);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((xPathExpression == null) ? 0 : xPathExpression.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		XPathTransform other = (XPathTransform) obj;
		if (!Objects.equals(xPathExpression, other.xPathExpression)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "XPathTransform [xPathExpression=" + xPathExpression + ", algorithm=" + algorithm + ", namespace="
				+ namespace + "]";
	}

}
