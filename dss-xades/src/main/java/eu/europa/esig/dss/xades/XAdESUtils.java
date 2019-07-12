package eu.europa.esig.dss.xades;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.ReferenceNotInitializedException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.xades.signature.XAdESBuilder;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public final class XAdESUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESUtils.class);
	
	private static final String TRANSFORMATION_EXCLUDE_SIGNATURE = "not(ancestor-or-self::ds:Signature)";
	private static final String TRANSFORMATION_XPATH_NODE_NAME = "XPath";
	
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
					byte[] bytes = getNodeBytes(sigObject);
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
		} else if (XAdESBuilder.HTTP_WWW_W3_ORG_2000_09_XMLDSIG_OBJECT.equals(referenceType) || XAdESBuilder.HTTP_WWW_W3_ORG_2000_09_XMLDSIG_MANIFEST.equals(referenceType)) {
			return true;
		// otherwise not a document
		} else {
			return false;
		}
	}
	
	/**
	 * Returns bytes of the given {@code node}
	 * @param node {@link Node} to get bytes for
	 * @return byte array
	 */
	public static byte[] getNodeBytes(Node node) {
		Node firstChild = node.getFirstChild();
		if (firstChild.getNodeType() == Node.ELEMENT_NODE) {
			byte[] bytes = DSSXMLUtils.serializeNode(firstChild);
			String str = new String(bytes);
			// TODO: better
			// remove <?xml version="1.0" encoding="UTF-8"?>
			str = str.substring(str.indexOf("?>") + 2);
			return str.getBytes();
		} else if (firstChild.getNodeType() == Node.TEXT_NODE) {
			String textContent = firstChild.getTextContent();
			if (Utils.isBase64Encoded(textContent)) {
				return Utils.fromBase64(firstChild.getTextContent());
			} else {
				return textContent.getBytes();
			}
		}
		return null;
	}
	
	/**
	 * Returns bytes of the original referenced data
	 * @param reference {@link Reference} to get bytes from
	 * @return byte array containing original data
	 */
	public static byte[] getReferenceOriginalContentBytes(Reference reference) {
		
		try {
			// returns bytes after transformation in case of enveloped signature
			Transforms transforms = reference.getTransforms();
			if (transforms != null) {
				Element transformsElement = transforms.getElement();
				NodeList transformChildNodes = transformsElement.getChildNodes();
				if (transformChildNodes != null && transformChildNodes.getLength() > 0) {
					for (int i = 0; i < transformChildNodes.getLength(); i++) {
						Node transformation = transformChildNodes.item(i);
						if (isEnvelopedTransform(transformation)) {
							return reference.getReferencedBytes();
						}
					    // if enveloped transformations are not applied to the signature go further and 
						// return bytes before transformation
					}
				}
			}
			
		} catch (XMLSecurityException e) {
			// if exception occurs during the transformations
			LOG.warn("Signature reference with id [{}] is corrupted or has an invalid format. "
					+ "Original data cannot be obtained. Reason: [{}]", reference.getId(), e.getMessage());
			
		}
		// otherwise bytes before transformation
		return getBytesBeforeTransformation(reference);
	}
	
	private static boolean isEnvelopedTransform(Node transformation) {
		final String algorithm = DomUtils.getValue(transformation, "@Algorithm");
		if (Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(algorithm)) {
			return true;
		} else if (Transforms.TRANSFORM_XPATH.equals(algorithm) || 
				Transforms.TRANSFORM_XPATH2FILTER.equals(algorithm)) {
			NodeList childNodes = transformation.getChildNodes();
			for (int j = 0; j < childNodes.getLength(); j++) {
				Node item = childNodes.item(j);
				if (Node.ELEMENT_NODE == item.getNodeType() && TRANSFORMATION_XPATH_NODE_NAME.equals(item.getLocalName()) &&
						TRANSFORMATION_EXCLUDE_SIGNATURE.equals(item.getTextContent())) {
					return true;
				}
			}
		}
		return false;
	}
	
	private static byte[] getBytesBeforeTransformation(Reference reference) {
		try {
			return reference.getContentsBeforeTransformation().getBytes();
		} catch (ReferenceNotInitializedException e) {
			// if exception occurs during an attempt to access reference original data
			LOG.warn("Original data is not provided for the reference with id [" + reference.getId() + "]. Reason: [{}]", e.getMessage());
		} catch (IOException | CanonicalizationException e) {
			// if exception occurs by another reason
			LOG.error("Unable to retrieve the content of reference with id [" + reference.getId() + "].", e);
		}
		// in case of exceptions return null value
		return null;
	}

	/**
	 * Returns {@link Digest} found in the given {@code element}
	 * @param element {@link Element} to get digest from
	 * @return {@link Digest}
	 */
	public static Digest getCertDigest(Element element, XPathQueryHolder xPathQueryHolder) {
		final Element certDigestElement = DomUtils.getElement(element, xPathQueryHolder.XPATH__CERT_DIGEST);
		if (certDigestElement == null) {
			return null;
		}
		
		final Element digestMethodElement = DomUtils.getElement(certDigestElement, xPathQueryHolder.XPATH__DIGEST_METHOD);
		final Element digestValueElement = DomUtils.getElement(element, xPathQueryHolder.XPATH__CERT_DIGEST_DIGEST_VALUE);
		if (digestMethodElement == null || digestValueElement == null) {
			return null;
		}
		
		final byte[] digestValue = Utils.fromBase64(digestValueElement.getTextContent());
		
		try {
			final String xmlAlgorithmName = digestMethodElement.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
			final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(xmlAlgorithmName);
			return new Digest(digestAlgorithm, digestValue);
		} catch (DSSException e) {
			LOG.warn("CertRef DigestMethod is not supported. Reason: {}", e.getMessage());
			return null;
		}
		
	}
	
	/**
	 * Returns {@link Digest} found in the given {@code revocationRefNode}
	 * @param revocationRefNode {@link Element} to get digest from
	 * @param xPathQueryHolder {@link XPathQueryHolder}
	 * @return {@link Digest}
	 */
	public static Digest getRevocationDigest(Element revocationRefNode, final XPathQueryHolder xPathQueryHolder) {
		final Element digestAlgorithmEl = DomUtils.getElement(revocationRefNode, xPathQueryHolder.XPATH__DAAV_DIGEST_METHOD);
		final Element digestValueEl = DomUtils.getElement(revocationRefNode, xPathQueryHolder.XPATH__DAAV_DIGEST_VALUE);
		
		DigestAlgorithm digestAlgo = null;
		byte[] digestValue = null;
		if (digestAlgorithmEl != null && digestValueEl != null) {
			final String xmlName = digestAlgorithmEl.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
			digestAlgo = DigestAlgorithm.forXML(xmlName);
			digestValue = Utils.fromBase64(digestValueEl.getTextContent());
			return new Digest(digestAlgo, digestValue);
		}
		return null;
	}

	/**
	 * Determines if the given {@code reference} refers to SignedProperties element
	 * @param reference {@link Reference} to check
	 * @return TRUE if the reference refers to the SignedProperties, FALSE otherwise
	 */
	public static boolean isSignedProperties(final Reference reference, final XPathQueryHolder xPathQueryHolder) {
		return xPathQueryHolder.XADES_SIGNED_PROPERTIES.equals(reference.getType());
	}

	/**
	 * Determines if the given {@code reference} refers to CounterSignature element
	 * @param reference {@link Reference} to check
	 * @return TRUE if the reference refers to the CounterSignature, FALSE otherwise
	 */
	public static boolean isCounerSignature(final Reference reference, final XPathQueryHolder xPathQueryHolder) {
		return xPathQueryHolder.XADES_COUNTERSIGNED_SIGNATURE.equals(reference.getType());
	}
	
	/**
	 * Checks if the given {@value reference} is linked to a <KeyInfo> element
	 * @param reference - {@link Reference} to check
	 * @param signature - {@link Element} signature the given {@value reference} belongs to
	 * @return - TRUE if the {@value reference} is a <KeyInfo> reference, FALSE otherwise
	 */
	public static boolean isKeyInfoReference(final Reference reference, final Element signature, final XPathQueryHolder xPathQueryHolder) {
		String uri = reference.getURI();
		uri = DomUtils.getId(uri);
		Element element = DomUtils.getElement(signature, "./" + xPathQueryHolder.XPATH_KEY_INFO + DomUtils.getXPathByIdAttribute(uri));
		if (element != null) {
			return true;
		}
		return false;
	}

}
