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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.model.DSSException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.util.Map.Entry;

/**
 * Transform processed by Apache {@code XMLSignatureInput} utils
 */
public abstract class ComplexTransform extends AbstractTransform {

	private static final long serialVersionUID = -2344414065328072642L;

	/** Internal object, used to build the Transformation */
	private Transform transformObject;

	/**
	 * Default constructor
	 *
	 * @param xmlDSigNamespace {@link DSSNamespace}
	 * @param algorithm {@link String} url
	 */
	protected ComplexTransform(DSSNamespace xmlDSigNamespace, String algorithm) {
		super(xmlDSigNamespace, algorithm);
	}
	
	private void buildTransformObject() {
		try {
			final Document document = DomUtils.buildDOM();
			final Element transformsDom = DomUtils.createElementNS(document, namespace, XMLDSigElement.TRANSFORMS);
			document.appendChild(transformsDom);
			createTransform(document, transformsDom);
			final NodeList childNodes = transformsDom.getFirstChild().getChildNodes();
			final Transform transformObject = new Transform(document, algorithm, childNodes);
			for (Entry<String, String> namespace : DomUtils.getCurrentNamespaces().entrySet()) {
				transformObject.setXPathNamespaceContext(namespace.getKey(), namespace.getValue());
			}
			this.transformObject = transformObject;
		} catch (XMLSecurityException e) {
			throw new DSSException(String.format("Cannot initialize a transform [%s]", algorithm), e);
		}
	}
	
	@Override
	public byte[] getBytesAfterTransformation(Node node) {
		if (transformObject == null) {
			buildTransformObject();
		}
		try {
			final XMLSignatureInput xmlSignatureInput = getXMLSignatureInput(node);
			final XMLSignatureInput xmlSignatureInputOut = transformObject.performTransform(xmlSignatureInput, true);
			return xmlSignatureInputOut.getBytes();
		} catch (IOException | XMLSecurityException e) {
			throw new DSSException(String.format("Cannot process transformation [%s] on the given DOM object. Reason : [%s]", 
					algorithm, e.getMessage()), e);
		}
	}

	/**
	 * Gets {@code XMLSignatureInput} for the given node
	 *
	 * @param node {@link Node}
	 * @return {@link XMLSignatureInput}
	 */
	protected XMLSignatureInput getXMLSignatureInput(Node node) {
		return new XMLSignatureInput(node);
	}

}
