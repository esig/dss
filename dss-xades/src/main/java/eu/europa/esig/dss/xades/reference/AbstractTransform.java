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

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;

public abstract class AbstractTransform implements DSSTransform {

	public static final String ALGORITHM_ATTRIBUTE_NAME = "Algorithm";
	public static final String DS_TRANSFORM = "ds:Transform";
	
	protected final String algorithm;
	protected String namespace = XMLSignature.XMLNS;
	
	public AbstractTransform(String algorithm) {
		this.algorithm = algorithm;
	}
	
	@Override
	public String getAlgorithm() {
		return this.algorithm;
	}
	
	@Override
	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transformDom = DomUtils.addElement(document, parentNode, namespace, DS_TRANSFORM);
		transformDom.setAttribute(ALGORITHM_ATTRIBUTE_NAME, algorithm);
		return transformDom;
	}
	
}
