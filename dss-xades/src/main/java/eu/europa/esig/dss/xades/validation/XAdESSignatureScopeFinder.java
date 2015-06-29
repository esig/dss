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
package eu.europa.esig.dss.xades.validation;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.validation.FullSignatureScope;
import eu.europa.esig.dss.validation.SignatureScope;
import eu.europa.esig.dss.validation.SignatureScopeFinder;

/**
 *
 */
public class XAdESSignatureScopeFinder implements SignatureScopeFinder<XAdESSignature> {

	private final List<String> transformationToIgnore = new ArrayList<String>();

	private final Map<String, String> presentableTransformationNames = new HashMap<String, String>();

	public XAdESSignatureScopeFinder() {

		// @see http://www.w3.org/TR/xmldsig-core/#sec-TransformAlg
		// those transformations don't change the content of the document
		transformationToIgnore.add("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
		transformationToIgnore.add("http://www.w3.org/2000/09/xmldsig#base64");
		transformationToIgnore.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
		transformationToIgnore.add("http://www.w3.org/2006/12/xml-c14n11#WithComments");
		transformationToIgnore.add("http://www.w3.org/2001/10/xml-exc-c14n#WithComments");


		// those transformations change the document and must be reported
		presentableTransformationNames.put("http://www.w3.org/2002/06/xmldsig-filter2", "XPath filtering");
		presentableTransformationNames.put("http://www.w3.org/TR/1999/REC-xpath-19991116", "XPath filtering");
		presentableTransformationNames.put("http://www.w3.org/TR/1999/REC-xslt-19991116", "XSLT Transform");

		presentableTransformationNames.put("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "Canonical XML 1.0 (omits comments)");
		presentableTransformationNames.put("http://www.w3.org/2006/12/xml-c14n11#", "Canonical XML 1.1 (omits comments)");
		presentableTransformationNames.put("http://www.w3.org/2001/10/xml-exc-c14n#", "Exclusive Canonical XML (omits comments)");
	}

	@Override
	public List<SignatureScope> findSignatureScope(final XAdESSignature xadesSignature) {

		final List<SignatureScope> result = new ArrayList<SignatureScope>();

		final Set<Element> unsignedObjects = new HashSet<Element>();
		unsignedObjects.addAll(xadesSignature.getSignatureObjects());
		final Set<Element> signedObjects = new HashSet<Element>();

		final List<Element> signatureReferences = xadesSignature.getSignatureReferences();
		for (final Element signatureReference : signatureReferences) {

			final String type = DSSXMLUtils.getValue(signatureReference, "@Type");
			if (xadesSignature.getXPathQueryHolder().XADES_SIGNED_PROPERTIES.equals(type)) {
				continue;
			}
			final String uri = DSSXMLUtils.getValue(signatureReference, "@URI");
			final List<String> transformations = getTransformationNames(signatureReference);
			if (StringUtils.isBlank(uri)) {
				// self contained document
				result.add(new XmlRootSignatureScope(transformations));
			} else if (uri.startsWith("#")) {
				// internal reference
				final boolean xPointerQuery = XPointerResourceResolver.isXPointerQuery(uri, true);
				if (xPointerQuery) {

					final String id = DSSXMLUtils.getIDIdentifier(signatureReference);
					final XPointerSignatureScope xPointerSignatureScope = new XPointerSignatureScope(id, uri);
					result.add(xPointerSignatureScope);
					continue;
				}
				final String xmlIdOfSignedElement = uri.substring(1);
				final String xPathString = XPathQueryHolder.XPATH_OBJECT + "[@Id='" + xmlIdOfSignedElement + "']";
				Element signedElement = DSSXMLUtils.getElement(xadesSignature.getSignatureElement(), xPathString);
				if (signedElement != null) {
					if (unsignedObjects.remove(signedElement)) {
						signedObjects.add(signedElement);
						result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations));
					}
				} else {
					signedElement = DSSXMLUtils
							.getElement(xadesSignature.getSignatureElement().getOwnerDocument().getDocumentElement(), "//*" + "[@Id='" + xmlIdOfSignedElement + "']");
					if (signedElement != null) {

						final String namespaceURI = signedElement.getNamespaceURI();
						if ((namespaceURI == null) || (!XAdESNamespaces.exists(namespaceURI) && !namespaceURI.equals(XMLSignature.XMLNS))) {
							signedObjects.add(signedElement);
							result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations));
						}
					}
				}
			} else {
				// detached file
				result.add(new FullSignatureScope(uri));
			}
		}
		return result;
	}

	private List<String> getTransformationNames(final Element signatureReference) {

		final NodeList nodeList = DSSXMLUtils.getNodeList(signatureReference, "./ds:Transforms/ds:Transform");
		final List<String> algorithms = new ArrayList<String>(nodeList.getLength());
		for (int ii = 0; ii < nodeList.getLength(); ii++) {

			final Element transformation = (Element) nodeList.item(ii);
			final String algorithm = DSSXMLUtils.getValue(transformation, "@Algorithm");
			if (transformationToIgnore.contains(algorithm)) {
				continue;
			}
			if (presentableTransformationNames.containsKey(algorithm)) {
				algorithms.add(presentableTransformationNames.get(algorithm));
			} else {
				algorithms.add(algorithm);
			}
		}
		return algorithms;
	}
}
