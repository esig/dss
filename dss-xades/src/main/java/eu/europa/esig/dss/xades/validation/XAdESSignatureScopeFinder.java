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

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.FullSignatureScope;
import eu.europa.esig.dss.validation.SignatureScope;
import eu.europa.esig.dss.validation.SignatureScopeFinder;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 *
 */
public class XAdESSignatureScopeFinder implements SignatureScopeFinder<XAdESSignature> {

	private final List<String> transformationToIgnore = new ArrayList<String>();

	private final Map<String, String> presentableTransformationNames = new HashMap<String, String>();

	public XAdESSignatureScopeFinder() {

		// @see http://www.w3.org/TR/xmldsig-core/#sec-TransformAlg
		// those transformations don't change the content of the document
		transformationToIgnore.add(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
		transformationToIgnore.add(Transforms.TRANSFORM_BASE64_DECODE);
		transformationToIgnore.add(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
		transformationToIgnore.add(Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS);
		transformationToIgnore.add(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS);

		// those transformations change the document and must be reported
		presentableTransformationNames.put(Transforms.TRANSFORM_XPATH2FILTER, "XPath filtering");
		presentableTransformationNames.put(Transforms.TRANSFORM_XPATH, "XPath filtering");
		presentableTransformationNames.put(Transforms.TRANSFORM_XSLT, "XSLT Transform");

		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, "Canonical XML 1.0 (omits comments)");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, "Canonical XML 1.1 (omits comments)");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, "Exclusive Canonical XML (omits comments)");
	}

	@Override
	public List<SignatureScope> findSignatureScope(final XAdESSignature xadesSignature) {

		final List<SignatureScope> result = new ArrayList<SignatureScope>();

		final Set<Element> unsignedObjects = new HashSet<Element>();
		unsignedObjects.addAll(xadesSignature.getSignatureObjects());
		final Set<Element> signedObjects = new HashSet<Element>();

		final List<Element> signatureReferences = xadesSignature.getSignatureReferences();
		for (final Element signatureReference : signatureReferences) {

			final String type = DomUtils.getValue(signatureReference, "@Type");
			if (xadesSignature.getXPathQueryHolder().XADES_SIGNED_PROPERTIES.equals(type)) {
				continue;
			}
			final String uri = DomUtils.getValue(signatureReference, "@URI");
			final List<String> transformations = getTransformationNames(signatureReference);
			if (Utils.isStringBlank(uri)) {
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
				Element signedElement = DomUtils.getElement(xadesSignature.getSignatureElement(), xPathString);
				if (signedElement != null) {
					if (unsignedObjects.remove(signedElement)) {
						signedObjects.add(signedElement);
						result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations));
					}
				} else {
					signedElement = DomUtils.getElement(xadesSignature.getSignatureElement().getOwnerDocument().getDocumentElement(),
							"//*" + "[@Id='" + xmlIdOfSignedElement + "']");
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
				result.add(new FullSignatureScope(DSSUtils.decodeUrl(uri)));
			}
		}
		return result;
	}

	private List<String> getTransformationNames(final Element signatureReference) {

		final NodeList nodeList = DomUtils.getNodeList(signatureReference, "./ds:Transforms/ds:Transform");
		final List<String> algorithms = new ArrayList<String>(nodeList.getLength());
		for (int ii = 0; ii < nodeList.getLength(); ii++) {

			final Element transformation = (Element) nodeList.item(ii);
			final String algorithm = DomUtils.getValue(transformation, "@Algorithm");
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
