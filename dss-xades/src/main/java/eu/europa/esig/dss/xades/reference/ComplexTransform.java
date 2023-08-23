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

	private Transform getTransformObject() {
		if (this.transformObject == null) {
			this.transformObject = buildTransformObject();
		}
		return this.transformObject;
	}

	/**
	 * Builds a {@code Transform} object
	 *
	 * @return {@link Transform}
	 */
	protected Transform buildTransformObject() {
		try {
			final Document document = DomUtils.buildDOM();
			final Element transformsDom = DomUtils.createElementNS(document, namespace, XMLDSigElement.TRANSFORMS);
			document.appendChild(transformsDom);
			createTransform(document, transformsDom);
			final NodeList childNodes = transformsDom.getFirstChild().getChildNodes();
			final Transform transform = new Transform(document, algorithm, childNodes);
			for (Entry<String, String> namespace : DomUtils.getCurrentNamespaces().entrySet()) {
				transform.setXPathNamespaceContext(namespace.getKey(), namespace.getValue());
			}
			return transform;
		} catch (XMLSecurityException e) {
			throw new DSSException(String.format("Cannot initialize a transform [%s]", algorithm), e);
		}
	}
	
	@Override
	@Deprecated
	public byte[] getBytesAfterTransformation(Node node) {
		return performTransform(new DSSTransformOutput(node)).getBytes();
	}

	@Override
	public DSSTransformOutput performTransform(DSSTransformOutput transformOutput) {
		try {
			Transform transform = getTransformObject();
			XMLSignatureInput xmlSignatureOutput = transform.performTransform(transformOutput.getXmlSignatureInput(), true);
			return new DSSTransformOutput(xmlSignatureOutput);
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
	 * @deprecated since DSS 5.13. To be removed.
	 */
	@Deprecated
	protected XMLSignatureInput getXMLSignatureInput(Node node) {
		return new XMLSignatureInput(node);
	}

}
