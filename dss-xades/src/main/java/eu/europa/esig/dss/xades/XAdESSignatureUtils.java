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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.xml.security.signature.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
					if (!DSSXMLUtils.isSignedProperties(reference, signature.getXAdESPaths())) {
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
		DSSDocument document = getDSObject(reference, signature);
		if (document != null)  {
			return document;
		}
		document = getDSManifest(reference, signature);
		if (document != null)  {
			return document;
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

	private static DSSDocument getDSObject(Reference reference, XAdESSignature signature) {
		if (reference.typeIsReferenceToObject() || Utils.isStringEmpty(reference.getType())) {
			String objectId = DomUtils.getId(reference.getURI());
			Node objectById = signature.getObjectById(objectId);
			if (objectById != null && objectById.hasChildNodes()) {
				byte[] bytes = DSSXMLUtils.getNodeBytes(objectById.getFirstChild());
				if (bytes != null) {
					return new InMemoryDocument(bytes, objectId, MimeType.XML);
				}
			}
		}
		return null;
	}

	private static DSSDocument getDSManifest(Reference reference, XAdESSignature signature) {
		if (reference.typeIsReferenceToManifest() || Utils.isStringEmpty(reference.getType())) {
			String manifestId = DomUtils.getId(reference.getURI());
			Node manifestById = signature.getManifestById(manifestId);
			if (manifestById != null) {
				byte[] bytes = DSSXMLUtils.getNodeBytes(manifestById);
				if (bytes != null) {
					return new InMemoryDocument(bytes, manifestId, MimeType.XML);
				}
			}
		}
		return null;
	}

}
