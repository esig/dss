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
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
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

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignatureScopeFinder.class);

	private static final String XP_OPEN = "xpointer(";

	private static final String XNS_OPEN = "xmlns(";

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

		final List<Reference> references = xadesSignature.getReferences();
		boolean isEverythingCovered = isEverythingCovered(xadesSignature);

		for (final Reference signatureReference : references) {
			if (isSignedProperties(xadesSignature, signatureReference.getType())) {
				continue;
			}
			final String uri = signatureReference.getURI();
			final List<String> transformations = getTransformationNames(signatureReference);
			if (Utils.isStringBlank(uri)) {
				// self contained document
				if (isEverythingCovered) {
					result.add(new XmlRootSignatureScope(transformations));
				} else {
					result.add(new XmlElementSignatureScope("", transformations));
				}
			} else if (uri.startsWith("#")) {
				final String xmlIdOfSignedElement = uri.substring(1);
				// internal reference
				if (isXPointerQuery(uri)) {
					final String id = DSSXMLUtils.getIDIdentifier(signatureReference.getElement());
					final XPointerSignatureScope xPointerSignatureScope = new XPointerSignatureScope(id, uri);
					result.add(xPointerSignatureScope);
				} else if (signatureReference.typeIsReferenceToObject()) {
					Node objectById = xadesSignature.getObjectById(uri);
					if (objectById != null) {
						result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations));
					}
				} else if (signatureReference.typeIsReferenceToManifest()) {
					Node manifestById = xadesSignature.getManifestById(uri);
					if (manifestById != null) {
						result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations));
					}
				} else {
					NodeList nodeList = DomUtils.getNodeList(xadesSignature.getSignatureElement().getOwnerDocument().getDocumentElement(),
							"//*" + DomUtils.getXPathByIdAttribute(uri));
					if (nodeList != null && nodeList.getLength() == 1) {
						Node signedElement = nodeList.item(0);
						final String namespaceURI = signedElement.getNamespaceURI();
						if ((namespaceURI == null) || (!XAdESNamespaces.exists(namespaceURI) && !namespaceURI.equals(XMLSignature.XMLNS))) {
							if (isEverythingCovered) {
								result.add(new XmlRootSignatureScope(transformations));
							} else {
								result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations));
							}
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

	private List<String> getTransformationNames(final Reference reference) {
		final List<String> algorithms = new ArrayList<String>();
		try {
			Transforms transforms = reference.getTransforms();
			if (transforms != null) {
				Element transformsElement = transforms.getElement();
				NodeList transfromChildNodes = transformsElement.getChildNodes();
				if (transfromChildNodes != null && transfromChildNodes.getLength() > 0) {
					for (int i = 0; i < transfromChildNodes.getLength(); i++) {
						Node transformation = transfromChildNodes.item(i);
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
				}
			}
		} catch (XMLSecurityException e) {
			LOG.warn("Unable to analyze trasnformations", e);
		}
		return algorithms;
	}

	/**
	 * Indicates if the given URI is an XPointer query.
	 *
	 * @param uriValue
	 *            URI to be analysed
	 * @return true if it is an XPointer query
	 */
	private boolean isXPointerQuery(String uriValue) {
		if (uriValue.isEmpty() || uriValue.charAt(0) != '#') {
			return false;
		}

		String decodedUri = DSSUtils.decodeUrl(uriValue);
		if (decodedUri == null) {
			return false;
		}

		final String[] parts = decodedUri.substring(1).split("\\s");
		int ii = 0;
		for (; ii < parts.length - 1; ++ii) {
			if (!parts[ii].endsWith(")") || !parts[ii].startsWith(XNS_OPEN)) {
				return false;
			}
		}
		if (!parts[ii].endsWith(")") || !parts[ii].startsWith(XP_OPEN)) {
			return false;
		}
		return true;
	}

	private boolean isSignedProperties(XAdESSignature signature, String type) {
		return signature.getXPathQueryHolder().XADES_SIGNED_PROPERTIES.equals(type);
	}

	public boolean isEverythingCovered(XAdESSignature signature) {
		Element parent = signature.getSignatureElement().getOwnerDocument().getDocumentElement();
		if (parent != null) {
			if (XPathQueryHolder.XMLE_SIGNATURE.equals(parent.getLocalName()) || (isRelatedToUri(parent, getIds(signature)))) {
				return true;
			}
		}
		return false;
	}

	private Set<String> getIds(XAdESSignature signature) {
		List<Reference> references = signature.getReferences();
		Set<String> result = new HashSet<String>();
		for (Reference reference : references) {
			if (!reference.typeIsReferenceToManifest() && !reference.typeIsReferenceToObject() && !isSignedProperties(signature, reference.getType())
					&& !isXPointerQuery(reference.getURI())) {
				result.add(DomUtils.getId(reference.getURI()));
			}
		}
		return result;

	}

	private boolean isRelatedToUri(Node currentNode, Set<String> ids) {
		String idValue = DSSXMLUtils.getIDIdentifier(currentNode);
		if (idValue == null) {
			return Utils.collectionSize(ids) == 1 && Utils.isStringBlank(ids.iterator().next());
		} else {
			return ids.contains(idValue) || ids.contains("");
		}
	}

}
