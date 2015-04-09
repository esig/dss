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
package eu.europa.esig.dss.xades.signature;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.xades.DSSTransform;

/**
 * This class implement the logic of {@code Transforms.TRANSFORM_XPATH}.
 *
 * // TODO (06/12/2014): Can be easily adapted to support more transformations
 *
 */
class DSSTransformXPath {

	private Document document;
	private DSSTransform dssTransform;

	public DSSTransformXPath(final DSSTransform dssTransform) {

		this.dssTransform = dssTransform;
		document = DSSXMLUtils.buildDOM();
		final Element transformDom = document.createElementNS(XMLSignature.XMLNS, XAdESSignatureBuilder.DS_TRANSFORM);
		document.appendChild(transformDom);

		XAdESSignatureBuilder.createTransform(document, dssTransform, transformDom);
	}

	public byte[] transform(final DSSDocument input) throws DSSException {
		try {
			final String dssTransformAlgorithm = dssTransform.getAlgorithm();
			final NodeList childNodes = document.getFirstChild().getChildNodes();
			final Transform transformObject = new Transform(document, dssTransformAlgorithm, childNodes);

			final byte[] bytes = input.getBytes();
			final XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(bytes);
			final XMLSignatureInput xmlSignatureInputOut = transformObject.performTransform(xmlSignatureInput);
			return xmlSignatureInputOut.getBytes();
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public byte[] transform(final Node input) throws DSSException {
		try {
			final String dssTransformAlgorithm = dssTransform.getAlgorithm();
			final NodeList childNodes = document.getFirstChild().getChildNodes();
			final Transform transformObject = new Transform(document, dssTransformAlgorithm, childNodes);

			final XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(input);
			final XMLSignatureInput xmlSignatureInputOut = transformObject.performTransform(xmlSignatureInput);
			return xmlSignatureInputOut.getBytes();
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}
}
