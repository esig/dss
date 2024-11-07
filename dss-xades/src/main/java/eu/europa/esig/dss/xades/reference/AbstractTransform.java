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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Objects;

/**
 * The abstract implementation of a transform
 */
public abstract class AbstractTransform implements DSSTransform {

	private static final long serialVersionUID = 7176619121506452500L;

	/** The algorithm url string */
	protected final String algorithm;

	/** The namespace */
	protected DSSNamespace namespace = XMLDSigNamespace.NS;

	/**
	 * Default constructor
	 *
	 * @param algorithm {@link String} algorithm url
	 */
	protected AbstractTransform(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * Constructor with namespace
	 *
	 * @param xmlDSigNamespace {@link DSSNamespace}
	 * @param algorithm {@link String}
	 */
	protected AbstractTransform(DSSNamespace xmlDSigNamespace, String algorithm) {
		this.namespace = xmlDSigNamespace;
		this.algorithm = algorithm;
	}
	
	@Override
	public String getAlgorithm() {
		return this.algorithm;
	}
	
	@Override
	public void setNamespace(DSSNamespace namespace) {
		this.namespace = namespace;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transformDom = DomUtils.addElement(document, parentNode, namespace, XMLDSigElement.TRANSFORM);
		transformDom.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), algorithm);
		return transformDom;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
		result = prime * result + ((namespace == null) ? 0 : namespace.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AbstractTransform other = (AbstractTransform) obj;
		if (!Objects.equals(algorithm, other.algorithm)) {
			return false;
		}
		if (!Objects.equals(namespace, other.namespace)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "DSSTransform [algorithm=" + algorithm + ", namespace=" + namespace + "]";
	}
	
}
