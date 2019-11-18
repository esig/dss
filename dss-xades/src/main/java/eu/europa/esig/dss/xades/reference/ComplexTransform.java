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

import java.io.IOException;
import java.util.Map.Entry;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.xades.signature.XAdESSignatureBuilder;

public abstract class ComplexTransform extends AbstractTransform {
	
	private Transform transformObject; // internal object, used to build the Transformation

	public ComplexTransform(String algorithm) {
		super(algorithm);
	}
	
	private void buildTransformObject() {
		try {
			final Document document = DomUtils.buildDOM();
			final Element transformsDom = document.createElementNS(namespace, XAdESSignatureBuilder.DS_TRANSFORMS);
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
	public byte[] getBytesAfterTranformation(Node node) {
		if (transformObject == null) {
			buildTransformObject();
		}
		try {
			final XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(node);
			final XMLSignatureInput xmlSignatureInputOut = transformObject.performTransform(xmlSignatureInput);
			return xmlSignatureInputOut.getBytes();
		} catch (IOException | XMLSecurityException e) {
			throw new DSSException(String.format("Cannot process transformation [%s] on the given DOM object. Reason : [%s]", 
					algorithm, e.getMessage()), e);
		}
	}

}
