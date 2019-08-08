package eu.europa.esig.dss.xades;

import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public final class XAdESSignatureUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESSignatureUtils.class);
	
	/**
	 * Returns list of original signed documents
	 * @param signature [{@link XAdESSignature} to find signed documents for
	 * @return list of {@link DSSDocument}s
	 */
	public static List<DSSDocument> getSignerDocuments(XAdESSignature signature) {
		signature.checkSignatureIntegrity();
		
		List<DSSDocument> result = new ArrayList<DSSDocument>();

		SignatureCryptographicVerification signatureCryptographicVerification = signature.getSignatureCryptographicVerification();
		if (!signatureCryptographicVerification.isSignatureValid()) {
			return result;
		}
		List<Reference> references = signature.getReferences();
		if (Utils.isCollectionNotEmpty(references)) {
			for (Reference reference : references) {
				if (isReferenceLinkedToDocument(reference, signature)) {
					DSSDocument referenceDocument = getReferenceDocument(reference, signature);
					if (referenceDocument != null) {
						result.add(referenceDocument);
					}
				}
			}
			
		}
		return result;
	}
	
	private static DSSDocument getReferenceDocument(Reference reference, XAdESSignature signature) {
		if (reference.typeIsReferenceToObject()) {
			List<Element> signatureObjects = signature.getSignatureObjects();
			for (Element sigObject : signatureObjects) {
				String objectId = sigObject.getAttribute("Id");
				if (Utils.endsWithIgnoreCase(reference.getURI(), objectId)) {
					byte[] bytes = DSSXMLUtils.getNodeBytes(sigObject);
					if (bytes != null) {
						return new InMemoryDocument(bytes, objectId);
					}
				}
			}
		} else {
			try {
				return new InMemoryDocument(reference.getReferencedBytes(), reference.getURI());
			} catch (XMLSignatureException e) {
				LOG.warn("Unable to retrieve reference {}", reference.getId(), e);
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("A referenced document not found for a reference with Id : [{}]", reference.getId());
		}
		return null;
	}
	
	/**
	 * Checks if the given {@value reference} is an occurrence of signed object
	 * @param reference - Reference to check
	 * @param signature - Signature, containing the given {@value reference}
	 * @return - TRUE if the given {@value reference} is a signed object, FALSE otherwise
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
