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

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.ContainerContentSignatureScope;
import eu.europa.esig.dss.validation.ContainerSignatureScope;
import eu.europa.esig.dss.validation.DigestSignatureScope;
import eu.europa.esig.dss.validation.FullSignatureScope;
import eu.europa.esig.dss.validation.SignatureScope;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Performs operations in order to find all signed data for a XAdES Signature
 */
public class XAdESSignatureScopeFinder extends AbstractSignatureScopeFinder<XAdESSignature> {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignatureScopeFinder.class);

	private static final String XP_OPEN = "xpointer(";

	private static final String XNS_OPEN = "xmlns(";

	private final Map<String, String> presentableTransformationNames = new HashMap<String, String>();

	public XAdESSignatureScopeFinder() {
		presentableTransformationNames.put(Transforms.TRANSFORM_ENVELOPED_SIGNATURE, "Enveloped Signature Transform");
		presentableTransformationNames.put(Transforms.TRANSFORM_BASE64_DECODE, "Base64 Decoding");
		
		presentableTransformationNames.put(Transforms.TRANSFORM_XPATH2FILTER, "XPath filtering");
		presentableTransformationNames.put(Transforms.TRANSFORM_XPATH, "XPath filtering");
		presentableTransformationNames.put(Transforms.TRANSFORM_XSLT, "XSLT Transform");
		
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, "Canonical XML 1.0 with Comments");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, "Canonical XML 1.1 with Comments");
		presentableTransformationNames.put(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS, "Exclusive XML Canonicalization 1.0 with Comments");

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
			byte[] referenceOriginalContentBytes = XAdESUtils.getReferenceOriginalContentBytes(signatureReference);
			if (Utils.isStringBlank(uri) && referenceOriginalContentBytes != null) {
				// self contained document
				if (isEverythingCovered) {
					result.add(new XmlRootSignatureScope(transformations, getDigest(referenceOriginalContentBytes)));
				} else {
					result.add(new XmlElementSignatureScope("", transformations, getDigest(referenceOriginalContentBytes)));
				}
			} else if (uri.startsWith("#")) {
				final String xmlIdOfSignedElement = uri.substring(1);
				// internal reference
				if (isXPointerQuery(uri)) {
					final String id = DSSXMLUtils.getIDIdentifier(signatureReference.getElement());
					// TODO: check and to do
					final XPointerSignatureScope xPointerSignatureScope = new XPointerSignatureScope(id, uri, 
							getDigest(XAdESUtils.getReferenceOriginalContentBytes(signatureReference)));
					result.add(xPointerSignatureScope);
				} else if (signatureReference.typeIsReferenceToObject()) {
					Node objectById = xadesSignature.getObjectById(uri);
					if (objectById != null) {
						result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations, getDigest(XAdESUtils.getNodeBytes(objectById))));
					}
				} else if (signatureReference.typeIsReferenceToManifest()) {
					Node manifestById = xadesSignature.getManifestById(uri);
					if (manifestById != null) {
						result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations, getDigest(XAdESUtils.getNodeBytes(manifestById))));
					}
				} else {
					NodeList nodeList = DomUtils.getNodeList(xadesSignature.getSignatureElement().getOwnerDocument().getDocumentElement(),
							"//*" + DomUtils.getXPathByIdAttribute(uri));
					if (nodeList != null && nodeList.getLength() == 1) {
						Node signedElement = nodeList.item(0);
						final String namespaceURI = signedElement.getNamespaceURI();
						if ((namespaceURI == null) || (!XAdESNamespaces.exists(namespaceURI) && !namespaceURI.equals(XMLSignature.XMLNS))) {
							if (isEverythingCovered) {
								result.add(new XmlRootSignatureScope(transformations, getDigest(XAdESUtils.getNodeBytes(signedElement))));
							} else {
								result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations, getDigest(XAdESUtils.getNodeBytes(signedElement))));
							}
						}
					}
				}
			} else if (Utils.isCollectionNotEmpty(xadesSignature.getDetachedContents())) {
				// detached file
				for (DSSDocument detachedDocument : xadesSignature.getDetachedContents()) {
					if (uri.equals(detachedDocument.getName())) {
						
						if (detachedDocument instanceof DigestDocument) {
							DigestDocument digestDocument = (DigestDocument) detachedDocument;
							result.add(new DigestSignatureScope(DSSUtils.decodeUrl(uri), digestDocument.getExistingDigest()));
							
						} else if (Utils.isCollectionNotEmpty(transformations)) {
							result.add(new XmlFullSignatureScope(DSSUtils.decodeUrl(uri), transformations, getDigest(DSSUtils.toByteArray(detachedDocument))));
							
						} else if (isASiCSArchive(xadesSignature, detachedDocument)) {
							result.add(new ContainerSignatureScope(DSSUtils.decodeUrl(uri), getDigest(DSSUtils.toByteArray(detachedDocument))));
							
							for (DSSDocument archivedDocument : xadesSignature.getContainerContents()) {
								result.add(new ContainerContentSignatureScope(DSSUtils.decodeUrl(archivedDocument.getName()), 
										getDigest(DSSUtils.toByteArray(archivedDocument))));
							}
							
						} else {
							result.add(new FullSignatureScope(DSSUtils.decodeUrl(uri), getDigest(DSSUtils.toByteArray(detachedDocument))));
							
						}
						
					}
				}
			}
		}
		// append detached documents with empty name
		if (Utils.isCollectionNotEmpty(xadesSignature.getDetachedContents())) {
			for (DSSDocument detachedDocument : xadesSignature.getDetachedContents()) {
				// can be only a Digest Document
				if (detachedDocument instanceof DigestDocument && Utils.isStringEmpty(detachedDocument.getName())) {
					DigestDocument digestDocument = (DigestDocument) detachedDocument;
					result.add(new DigestSignatureScope(detachedDocument.getName(), digestDocument.getExistingDigest()));
				}
			}
		}
		return result;
	}

	/**
	 * Returns a list of transformations contained in the {@code reference}
	 * @param reference {@link Reference} to find transformations for
	 * @return list of transformation names
	 */
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
						if (Node.ELEMENT_NODE == transformation.getNodeType()) {
							algorithms.add(buildTransformationName(transformation));
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
	 * Returns a complete description string for the given transformation node
	 * @param transformation {@link Node} containing a signle reference transformation information
	 * @return transformation description name
	 */
	private String buildTransformationName(Node transformation) {
		String algorithm = DomUtils.getValue(transformation, "@Algorithm");
		if (presentableTransformationNames.containsKey(algorithm)) {
			algorithm = presentableTransformationNames.get(algorithm);
		}
		StringBuilder stringBuilder = new StringBuilder(algorithm);
		if (transformation.hasChildNodes()) {
			NodeList childNodes = transformation.getChildNodes();
			stringBuilder.append(" (");
			boolean hasValues = false;
			for (int j = 0; j < childNodes.getLength(); j++) {
				Node parameterNode = childNodes.item(j);
				if (Node.ELEMENT_NODE != parameterNode.getNodeType()) {
					continue;
				}
				Node parameterValueNode = parameterNode.getFirstChild();
				if (parameterValueNode != null && Node.TEXT_NODE == parameterValueNode.getNodeType() &&
						Utils.isStringNotBlank(parameterValueNode.getTextContent())) {
					if (hasValues) {
						stringBuilder.append("; ");
					}
					stringBuilder.append(parameterNode.getLocalName()).append(": ");
					stringBuilder.append(parameterValueNode.getTextContent());
					hasValues = true;
				}
			}
			stringBuilder.append(")");
		}
		return stringBuilder.toString();
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
