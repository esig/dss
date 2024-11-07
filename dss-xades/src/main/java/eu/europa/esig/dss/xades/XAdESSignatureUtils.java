/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades;


import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.xml.security.signature.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Contains util methods for dealing with XAdES
 */
public final class XAdESSignatureUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignatureUtils.class);

	/**
	 * Empty constructor
	 */
	private XAdESSignatureUtils() {
		// empty
	}
	
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
		if (document != null) {
			return document;
		}
		document = getDSManifest(reference, signature);
		if (document != null) {
			return document;
		}

		// if not an object or object has not been found
		try {
			byte[] referencedBytes = reference.getReferencedBytes();
			if (referencedBytes != null) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Retrieved reference bytes: ");
					LOG.debug(new String(referencedBytes));
				}
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
		try {
			if (reference.typeIsReferenceToObject() || Utils.isStringEmpty(reference.getType())) {
				String objectId = DomUtils.getId(reference.getURI());
				Node objectById = DSSXMLUtils.getObjectById(signature.getSignatureElement(), objectId);
				if (objectById != null && objectById.hasChildNodes()) {
					try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
						NodeList childNodes = objectById.getChildNodes();
						for (int i = 0; i < childNodes.getLength(); i++) {
							byte[] nodeBytes = DomUtils.getNodeBytes(childNodes.item(i));
							if (nodeBytes != null) {
								baos.write(nodeBytes);
							}
						}
						byte[] bytes = baos.toByteArray();
						return new InMemoryDocument(bytes, objectId, MimeTypeEnum.XML);
					}
				}
			}
		} catch (Exception e) {
			LOG.debug("An error occurred during an attempt to extract signed object. Reason : {}", e.getMessage());
		}
		return null;
	}

	private static DSSDocument getDSManifest(Reference reference, XAdESSignature signature) {
		try {
			if (reference.typeIsReferenceToManifest() || Utils.isStringEmpty(reference.getType())) {
				String manifestId = DomUtils.getId(reference.getURI());
				Node manifestById = DSSXMLUtils.getManifestById(signature.getSignatureElement(), manifestId);
				if (manifestById != null) {
					byte[] bytes = DomUtils.getNodeBytes(manifestById);
					if (bytes != null) {
						return new InMemoryDocument(bytes, manifestId, MimeTypeEnum.XML);
					}
				}
			}
		} catch (Exception e) {
			LOG.debug("An error occurred during an attempt to extract signed manifest. Reason : {}", e.getMessage());
		}
		return null;
	}

	/**
	 * This method verifies whether the ds:KeyInfo element is signed by the signature
	 *
	 * @param signature {@link XAdESSignature} to verify
	 * @return TRUE if ds:KeyInfo element is signed, FALSE otherwise
	 */
	public static boolean isKeyInfoCovered(XAdESSignature signature) {
		List<ReferenceValidation> referenceValidations = signature.getReferenceValidations();
		if (Utils.isCollectionNotEmpty(referenceValidations)) {
			for (ReferenceValidation referenceValidation : referenceValidations) {
				if (DigestMatcherType.KEY_INFO.equals(referenceValidation.getType()) && referenceValidation.isFound() && referenceValidation.isIntact()) {
					return true;
				}
			}
		}
		return false;
	}

}
