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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.xmldsig.definition.XMLDSigAttribute;
import eu.europa.esig.xmldsig.definition.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.reference.XAdESReferenceValidation;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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

	/** The manifest */
	private final Manifest manifest;

	/**
	 * Default constructor
	 *
	 * @param manifestElement {@link Element} ds:Manifest element
	 * @param detachedContents a list of detached manifested {@link DSSDocument}s
	 */
	public ManifestValidator(final Element manifestElement, final List<DSSDocument> detachedContents) {
		this(initManifest(manifestElement), detachedContents);
	}

	/**
	 * The constructor with instantiated {@code org.apache.xml.security.signature.Manifest} and detached contents
	 *
	 * @param manifest {@link Manifest}
	 * @param detachedContents a list of detached {@link DSSDocument}s
	 */
	public ManifestValidator(final Manifest manifest, final List<DSSDocument> detachedContents) {
		this(manifest);
		initDetachedSignatureResolvers(manifest, detachedContents);
	}

	/**
	 * The constructor with instantiated {@code org.apache.xml.security.signature.Manifest}
	 *
	 * @param manifest {@link Manifest}
	 */
	public ManifestValidator(final Manifest manifest) {
		this.manifest = manifest;
	}

	private static Manifest initManifest(final Element manifestElement) {
		try {
			return new Manifest(manifestElement, "");
		} catch (XMLSecurityException e) {
			throw new DSSException(
					String.format("Unable to instantiate a ManifestValidator. Reason : %s", e.getMessage()), e);
		}
	}

	private static void initDetachedSignatureResolvers(Manifest manifest, List<DSSDocument> detachedContents) {
		List<DigestAlgorithm> usedReferenceDigestAlgos = DSSXMLUtils.getReferenceDigestAlgos(manifest.getElement());
		for (DigestAlgorithm digestAlgorithm : usedReferenceDigestAlgos) {
			manifest.addResourceResolver(new DetachedSignatureResolver(detachedContents, digestAlgorithm));
		}
	}

	/**
	 * Validates the manifest and returns a list of {@code ReferenceValidation}s
	 *
	 * @return a list of {@link ReferenceValidation}s
	 */
	public List<ReferenceValidation> validate() {
		LOG.info("Validation of the manifest references ...");

		List<Reference> references = DSSXMLUtils.extractReferences(manifest);
		if (Utils.isCollectionEmpty(references)) {
			LOG.warn("No references found inside the ds:Manifest element!");
			return Collections.emptyList();
		}

		List<ReferenceValidation> referenceValidations = new ArrayList<>();
		for (Reference reference : references) {
			try {
				XAdESReferenceValidation refValidation = createReferenceValidation(reference);

				boolean refFound = DSSXMLUtils.isAbleToDeReferenceContent(reference);
				refValidation.setFound(refFound);

				boolean isDuplicated = DSSXMLUtils.isReferencedContentAmbiguous(
						manifest.getDocument(), refValidation.getUri());
				refValidation.setDuplicated(isDuplicated);

				if (refFound && !isDuplicated) {
					refValidation.setIntact(reference.verify());
				}
				referenceValidations.add(refValidation);

			} catch (Exception e) {
				LOG.warn("Unable to verify reference with Id [{}] : {}", reference.getId(), e.getMessage(), e);
			}
		}
		return referenceValidations;
	}

	private XAdESReferenceValidation createReferenceValidation(Reference reference) {
		XAdESReferenceValidation refValidation = new XAdESReferenceValidation(reference);
		refValidation.setType(DigestMatcherType.MANIFEST_ENTRY);
		refValidation.setDigest(DSSXMLUtils.getReferenceDigest(reference));
		refValidation.setTransformationNames(getTransformNames(reference.getElement()));
		return refValidation;
	}
	
	private List<String> getTransformNames(Element refNode) {
		List<String> transformNames = new ArrayList<>();
		NodeList nodeList = DomUtils.getNodeList(refNode, XMLDSigPaths.TRANSFORMS_TRANSFORM_PATH);
		if (nodeList != null && nodeList.getLength() > 0) {
			for (int ii = 0; ii < nodeList.getLength(); ii++) {
				Element transformElement = (Element) nodeList.item(ii);
				String algorithm = transformElement.getAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName());
				if (Utils.isStringNotBlank(algorithm)) {
					transformNames.add(algorithm);
				}
			}
		}
		return transformNames;
	}

}
