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
package eu.europa.esig.dss.xades.validation.scope;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.xml.security.signature.Reference;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.scope.ContainerContentSignatureScope;
import eu.europa.esig.dss.validation.scope.ContainerSignatureScope;
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.ManifestEntrySignatureScope;
import eu.europa.esig.dss.validation.scope.ManifestSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESUtils;
import eu.europa.esig.dss.xades.reference.XAdESReferenceValidation;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

/**
 * Performs operations in order to find all signed data for a XAdES Signature
 */
public class XAdESSignatureScopeFinder extends AbstractSignatureScopeFinder<XAdESSignature> {
	
	@Override
	public List<SignatureScope> findSignatureScope(final XAdESSignature xadesSignature) {

		final List<SignatureScope> result = new ArrayList<SignatureScope>();
		boolean isEverythingCovered = isEverythingCovered(xadesSignature);
		
		List<ReferenceValidation> referenceValidations = xadesSignature.getReferenceValidations();
		for (ReferenceValidation referenceValidation : referenceValidations) {
			if (DigestMatcherType.SIGNED_PROPERTIES.equals(referenceValidation.getType()) || 
					DigestMatcherType.KEY_INFO.equals(referenceValidation.getType()) ) {
				// not a subject for the Signature Scope
				continue;
			}
			if (!(referenceValidation instanceof XAdESReferenceValidation)) {
				continue;
			}
			XAdESReferenceValidation xadesReferenceValidation = (XAdESReferenceValidation) referenceValidation;
			
			final String id = xadesReferenceValidation.getId();
			final String uri = xadesReferenceValidation.getUri();
			final String xmlIdOfSignedElement = DomUtils.getId(uri);
			final List<String> transformations = xadesReferenceValidation.getTransformationNames();
			
			if (xadesReferenceValidation.isFound() && DigestMatcherType.XPOINTER.equals(xadesReferenceValidation.getType())) {
				result.add(new XPointerSignatureScope(id, uri, getDigest(xadesReferenceValidation.getOriginalContentBytes())));
				
			} else if (xadesReferenceValidation.isFound() && DigestMatcherType.OBJECT.equals(xadesReferenceValidation.getType())) {
				Node objectById = xadesSignature.getObjectById(uri);
				if (objectById != null) {
					result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations, getDigest(XAdESUtils.getNodeBytes(objectById))));
				}
				
			} else if (xadesReferenceValidation.isFound() && DigestMatcherType.MANIFEST.equals(xadesReferenceValidation.getType())) {
            	result.add(new ManifestSignatureScope(xadesReferenceValidation.getName(), xadesReferenceValidation.getDigest(), 
            			xadesReferenceValidation.getTransformationNames()));
				for (ReferenceValidation manifestEntry : xadesReferenceValidation.getDependentValidations()) {
					if (manifestEntry.getName() != null) {
						// try to get document digest from list of detached contents
						List<SignatureScope> detachedResult = getFromDetachedContent(xadesSignature, transformations, manifestEntry.getName());
						if (Utils.isCollectionNotEmpty(detachedResult)) {
							result.addAll(detachedResult);
						} else if (manifestEntry.getDigest() != null) {
							// if the relative detached content is not found, store the reference value
							result.add(new ManifestEntrySignatureScope(manifestEntry.getName(), manifestEntry.getDigest(), 
									xadesReferenceValidation.getName(), manifestEntry.getTransformationNames()));
						}
					}
				}
				
			} else if (xadesReferenceValidation.isFound() && Utils.isStringBlank(uri)) {
				byte[] originalContentBytes = xadesReferenceValidation.getOriginalContentBytes();
				if (originalContentBytes != null) {
					// self contained document
					if (isEverythingCovered) {
						result.add(new XmlRootSignatureScope(transformations, getDigest(originalContentBytes)));
					} else {
						result.add(new XmlElementSignatureScope("", transformations, getDigest(originalContentBytes)));
					}
				}
				
			} else if (DomUtils.isElementReference(uri)) {
				NodeList nodeList = DomUtils.getNodeList(xadesSignature.getSignatureElement().getOwnerDocument().getDocumentElement(),
						"//*" + DomUtils.getXPathByIdAttribute(uri));
				if (nodeList != null && nodeList.getLength() == 1) {
					Node signedElement = nodeList.item(0);
					if (isEverythingCovered) {
						result.add(new XmlRootSignatureScope(transformations, getDigest(XAdESUtils.getNodeBytes(signedElement))));
					} else {
						result.add(new XmlElementSignatureScope(xmlIdOfSignedElement, transformations, getDigest(XAdESUtils.getNodeBytes(signedElement))));
					}
				}
				
			} else if (Utils.isCollectionNotEmpty(xadesSignature.getDetachedContents())) {
				// detached file
				result.addAll(getFromDetachedContent(xadesSignature, transformations, uri));
				
			}
		}
		// append detached documents with empty name
		if (Utils.isCollectionNotEmpty(xadesSignature.getDetachedContents())) {
			for (DSSDocument detachedDocument : xadesSignature.getDetachedContents()) {
				// can be only a Digest Document
				if (detachedDocument instanceof DigestDocument && Utils.isStringEmpty(detachedDocument.getName())) {
					DigestDocument digestDocument = (DigestDocument) detachedDocument;
					result.add(new DigestSignatureScope(null, digestDocument.getExistingDigest()));
				}
			}
		}
		return result;
		
	}
	
	private List<SignatureScope> getFromDetachedContent(final XAdESSignature xadesSignature, final List<String> transformations, final String uri) {
		List<SignatureScope> detachedSignatureScopes = new ArrayList<SignatureScope>();
		for (DSSDocument detachedDocument : xadesSignature.getDetachedContents()) {
			
			if (uri.equals(detachedDocument.getName())) {
				if (detachedDocument instanceof DigestDocument) {
					DigestDocument digestDocument = (DigestDocument) detachedDocument;
					detachedSignatureScopes.add(new DigestSignatureScope(DSSUtils.decodeUrl(uri), digestDocument.getExistingDigest()));
					
				} else if (Utils.isCollectionNotEmpty(transformations)) {
					detachedSignatureScopes.add(new XmlFullSignatureScope(DSSUtils.decodeUrl(uri), transformations, getDigest(DSSUtils.toByteArray(detachedDocument))));
					
				} else if (isASiCSArchive(xadesSignature, detachedDocument)) {
					detachedSignatureScopes.add(new ContainerSignatureScope(DSSUtils.decodeUrl(uri), getDigest(DSSUtils.toByteArray(detachedDocument))));
					for (DSSDocument archivedDocument : xadesSignature.getContainerContents()) {
						detachedSignatureScopes.add(new ContainerContentSignatureScope(DSSUtils.decodeUrl(archivedDocument.getName()), 
								getDigest(DSSUtils.toByteArray(archivedDocument))));
					}
					
				} else {
					detachedSignatureScopes.add(new FullSignatureScope(DSSUtils.decodeUrl(uri), getDigest(DSSUtils.toByteArray(detachedDocument))));
					
				}
			}
		}
		return detachedSignatureScopes;
	}

	public boolean isEverythingCovered(XAdESSignature signature) {
		Element parent = signature.getSignatureElement().getOwnerDocument().getDocumentElement();
		if (parent != null) {
			if (isRelatedToUri(parent, getIds(signature))) {
				return true;
			}
		}
		return false;
	}

	private Set<String> getIds(XAdESSignature signature) {
		List<Reference> references = signature.getReferences();
		Set<String> result = new HashSet<String>();
		for (Reference reference : references) {
			if (!reference.typeIsReferenceToManifest() && !reference.typeIsReferenceToObject() && !XAdESUtils.isSignedProperties(reference, signature.getXPathQueryHolder())
					&& !DomUtils.isXPointerQuery(reference.getURI())) {
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
