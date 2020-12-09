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
package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.xml.security.signature.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains util methods for dealing with XAdES
 */
public final class XAdESSignatureUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignatureUtils.class);
	
	/**
	 * Returns list of original signed documents
	 * @param signature [{@link XAdESSignature} to find signed documents for
	 * @return list of {@link DSSDocument}s
	 */
	public static List<DSSDocument> getSignerDocuments(XAdESSignature signature) {
		List<DSSDocument> result = new ArrayList<>();

		SignatureCryptographicVerification signatureCryptographicVerification = signature.getSignatureCryptographicVerification();
		if (!signatureCryptographicVerification.isSignatureValid()) {
			return result;
		}
		List<Reference> references = signature.getReferences();
		if (Utils.isCollectionNotEmpty(references)) {
			for (Reference reference : references) {
				try {
					if (isReferenceLinkedToDocument(reference, signature)) {
						DSSDocument referenceDocument = getReferenceDocument(reference, signature);
						if (referenceDocument != null) {
							result.add(referenceDocument);
						}
					}
				} catch (DSSException e) {
					LOG.warn("Not able to extract an original content for a reference with name '{}' and URI '{}'. "
							+ "Reason : {}", reference.getId(), reference.getURI(), e.getMessage());
				}
			}
			
		}
		return result;
	}
	
	private static DSSDocument getReferenceDocument(Reference reference, XAdESSignature signature) {
		if (reference.typeIsReferenceToObject()) {
			List<Element> signatureObjects = signature.getSignatureObjects();
			for (Element sigObject : signatureObjects) {
				Node referencedObject = sigObject;
				String objectId = sigObject.getAttribute(XMLDSigAttribute.ID.getAttributeName());
				if (Utils.endsWithIgnoreCase(reference.getURI(), objectId)) {
					if (reference.typeIsReferenceToObject() && sigObject.hasChildNodes()) {
						referencedObject = sigObject.getFirstChild();
					}
					byte[] bytes = DSSXMLUtils.getNodeBytes(referencedObject);
					if (bytes != null) {
						return new InMemoryDocument(bytes, objectId);
					}
				}
			}
		}
		
		// if not an object or object has not been found
		try {
			byte[] referencedBytes = reference.getReferencedBytes();
			if (referencedBytes != null) {
				return new InMemoryDocument(referencedBytes, reference.getURI());
			}
			LOG.warn("Reference bytes returned null value : {}", reference.getId());
		} catch (Exception e) {
			LOG.warn("Unable to retrieve reference {}. Reason : {}", reference.getId(), e.getMessage(), e);
		}
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("A referenced document not found for a reference with Id : [{}]", reference.getId());
		}
		return null;
	}
	
	/**
	 * Checks if the given {@code reference} is an occurrence of signed object
	 * @param reference - Reference to check
	 * @param signature - Signature, containing the given {@code reference}
	 * @return - TRUE if the given {@code reference} is a signed object, FALSE otherwise
	 */
	private static boolean isReferenceLinkedToDocument(Reference reference, XAdESSignature signature) {
		String referenceType = reference.getType();
		// if type is not declared
		if (Utils.isStringEmpty(referenceType)) {
			String referenceUri = reference.getURI();
			referenceUri = DomUtils.getId(referenceUri);
			Element element = DomUtils.getElement(signature.getSignatureElement(), "./*" + DomUtils.getXPathByIdAttribute(referenceUri));
			if (element == null) { // if element is out of the signature node, it is a document
				return true;
			} else { // otherwise not a document
				return false;
			}
		// if type refers to object or manifest - it is a document
		} else if (DSSXMLUtils.isObjectReferenceType(referenceType) || DSSXMLUtils.isManifestReferenceType(referenceType)) {
			return true;
		// otherwise not a document
		} else {
			return false;
		}
	}

}
