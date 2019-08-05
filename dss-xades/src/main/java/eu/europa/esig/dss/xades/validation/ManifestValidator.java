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
import java.util.Arrays;
import java.util.List;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * This class validates a ds:Manifest element against external files
 * 
 * <pre>
 * {@code
 * 	<ds:Manifest Id="manifest">
 * 		<ds:Reference URI="l_19420170726bg.pdf">
 * 			<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
 * 			<ds:DigestValue>EUcwRQ....</ds:DigestValue>
 * 		</ds:Reference>
 * 		<ds:Reference URI="l_19420170726cs.pdf">
 * 			<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
 * 			<ds:DigestValue>NQNnr+F...</ds:DigestValue>
 * 		</ds:Reference>
 * 		...
 * 	</ds:Manifest>
 * }
 * </pre>
 * 
 */
public class ManifestValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ManifestValidator.class);
	
	private static final String ALGORITHM_ATTRIBUTE = "Algorithm";

	private final Element signatureElement;
	private final Node manifestNode;
	private final List<DSSDocument> detachedContents;
	private final XPathQueryHolder xPathQueryHolder;

	ManifestValidator(Element signatureElement, Node manifestNode, List<DSSDocument> detachedContents, XPathQueryHolder xPathQueryHolder) {
		this.signatureElement = signatureElement;
		this.manifestNode = manifestNode;
		this.detachedContents = detachedContents;
		this.xPathQueryHolder = xPathQueryHolder;
	}

	List<ReferenceValidation> validate() {

		LOG.info("Validation of the manifest references ...");

		List<ReferenceValidation> result = new ArrayList<ReferenceValidation>();

		NodeList nodeList = DomUtils.getNodeList(manifestNode, "./ds:Reference");
		if (nodeList != null && nodeList.getLength() > 0) {
			for (int i = 0; i < nodeList.getLength(); i++) {

				Element refNode = (Element) nodeList.item(i);
				String uri = refNode.getAttribute("URI");
				
				if (DomUtils.isElementReference(uri)) {
					result.add(getInternalReferenceValidation(refNode, uri));
				} else {
					result.add(getDetachedReferenceValidation(refNode, uri));
				}
			}
		}

		return result;
	}
	
	private List<String> getTransformNames(Element refNode) {
		List<String> transfromNames = new ArrayList<String>();
		NodeList nodeList = DomUtils.getNodeList(refNode, xPathQueryHolder.XPATH__DS_TRANSFORM);
		if (nodeList != null && nodeList.getLength() > 0) {
			for (int ii = 0; ii < nodeList.getLength(); ii++) {
				Element transformElement = (Element) nodeList.item(ii);
				String algorithm = transformElement.getAttribute(ALGORITHM_ATTRIBUTE);
				if (Utils.isStringNotBlank(algorithm)) {
					transfromNames.add(algorithm);
				}
			}
		}
		return transfromNames;
	}
	
	private ReferenceValidation getInternalReferenceValidation(final Element refNode, final String uri) {
		ReferenceValidation refValidation = getReferenceValidationWithDigest(refNode, uri);
		NodeList nodeList = DomUtils.getNodeList(signatureElement.getOwnerDocument().getDocumentElement(),
				"//*" + DomUtils.getXPathByIdAttribute(uri));
		if (nodeList != null && nodeList.getLength() == 1) {
			refValidation.setFound(true);
			refValidation.setIntact(isIntact(refValidation, nodeList.item(0)));
		} else {
			refValidation.setFound(false);
		}
		return refValidation;
	}
	
	private ReferenceValidation getDetachedReferenceValidation(final Element refNode, final String uri) {
		ReferenceValidation refValidation = getReferenceValidationWithDigest(refNode, uri);
		DSSDocument doc = findByFilename(uri);
		if (doc != null) {
			refValidation.setFound(true);
			refValidation.setIntact(isIntact(refValidation, doc));
		} else {
			refValidation.setFound(false);
		}
		return refValidation;
	}
	
	private ReferenceValidation getReferenceValidationWithDigest(final Element refNode, final String uri) {
		ReferenceValidation refValidation = new ReferenceValidation();
		refValidation.setType(DigestMatcherType.MANIFEST_ENTRY);
		refValidation.setName(uri);
		Digest digest = getReferenceDigest(refNode);
		refValidation.setDigest(digest);
		refValidation.setTransformationNames(getTransformNames(refNode));
		return refValidation;
	}

	private Digest getReferenceDigest(Element refNode) {
		try {
			String digestAlgoUri = DomUtils.getValue(refNode, xPathQueryHolder.XPATH__DIGEST_METHOD_ALGORITHM);
			DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(digestAlgoUri);
			String digestValueB64 = DomUtils.getValue(refNode, xPathQueryHolder.XPATH__DIGEST_VALUE);
			return new Digest(digestAlgorithm, Utils.fromBase64(digestValueB64));
		} catch (Exception e) {
			LOG.warn("Unable to extract the digest combination : {}", e.getMessage());
			return null;
		}
	}

	private DSSDocument findByFilename(String filename) {
		for (DSSDocument dssDocument : detachedContents) {
			if (Utils.areStringsEqual(filename, dssDocument.getName())) {
				return dssDocument;
			}
		}
		return null;
	}

	private boolean isIntact(final ReferenceValidation referenceValidation, DSSDocument doc) {
		Digest digest = referenceValidation.getDigest();
		if (digest == null) {
			return false;
		}
		try {
			if (Utils.isCollectionNotEmpty(referenceValidation.getTransformationNames())) {
				Document documentDOM = DomUtils.buildDOM(doc);
				return isIntact(referenceValidation, documentDOM);
			} else {
				String documentDigestB64 = doc.getDigest(digest.getAlgorithm());
				return Arrays.equals(digest.getValue(), Utils.fromBase64(documentDigestB64));
			}
		} catch (Exception e) {
			LOG.warn("Unable to verify integrity for document '{}' : {}", doc.getName(), e.getMessage());
			return false;
		}
	}
	
	private boolean isIntact(final ReferenceValidation referenceValidation, Node node) {
		Digest digest = referenceValidation.getDigest();
		if (digest == null) {
			return false;
		}
		try {
			List<Transform> transforms = getTransforms(referenceValidation.getTransformationNames());
			byte[] bytesAfterTransforms = getBytesAfterTransforms(node, transforms);
			return Arrays.equals(digest.getValue(), DSSUtils.digest(digest.getAlgorithm(), bytesAfterTransforms));
		} catch (Exception e) {
			LOG.warn("Unable to verify integrity for element '{}' : {}", node.getLocalName(), e.getMessage());
			return false;
		}
	}

	private List<Transform> getTransforms(List<String> transformNames) throws InvalidTransformException {
		List<Transform> transforms = new ArrayList<Transform>();
		for (String algorithm : transformNames) {
			transforms.add(new Transform(signatureElement.getOwnerDocument(), algorithm));
		}
		return transforms;
	}
	
	private byte[] getBytesAfterTransforms(Node nodeToTransform, final List<Transform> transforms) throws DSSException {
		try {
			XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodeToTransform);
			for (Transform transform : transforms) {
				xmlSignatureInput = transform.performTransform(xmlSignatureInput);
			}
			return xmlSignatureInput.getBytes();
		} catch (Exception e) {
			throw new DSSException("An error occurred during applying of transformations. Transforms cannot be performed!");
		}
	}

}
