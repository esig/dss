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

import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigNamespace;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Objects;

/**
 * The XSLT transform
 */
public class XsltTransform extends ComplexTransform {

	private static final long serialVersionUID = -5119986978252813925L;

	/** The document to be added */
	private final Document content;

	/**
	 * Default constructor
	 *
	 * @param content {@link Document}
	 */
	public XsltTransform(Document content) {
		this(XMLDSigNamespace.NS, content);
	}

	/**
	 * Constructor wit namespace
	 *
	 * @param xmlDSigNamespace {@link DSSNamespace}
	 * @param content {@link Document}
	 */
	public XsltTransform(DSSNamespace xmlDSigNamespace, Document content) {
		super(xmlDSigNamespace, Transforms.TRANSFORM_XSLT);
		Objects.requireNonNull(content, "The content cannot be null!");
		this.content = content;
	}
	
	@Override
	public Element createTransform(Document document, Element parentNode) {
		final Element transform = super.createTransform(document, parentNode);
		final Document clonedNode = (Document) content.cloneNode(true);
		final Element contextDocumentElement = clonedNode.getDocumentElement();
		document.adoptNode(contextDocumentElement);
		return (Element) transform.appendChild(contextDocumentElement);
	}

}
