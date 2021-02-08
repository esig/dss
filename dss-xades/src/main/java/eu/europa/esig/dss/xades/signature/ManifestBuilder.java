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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.ReferenceBuilder;
import eu.europa.esig.dss.xades.reference.ReferenceProcessor;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.List;

/**
 * This class builds a ds:Manifest element
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
public class ManifestBuilder {

	/** Defines the default id for the Manifest element if none is provided */
	private static final String DEFAULT_MANIFEST_ID = "manifest";

	private static final DSSNamespace DEFAULT_NAMESPACE = XAdESNamespaces.XMLDSIG;

	/** The manifest id */
	private final String manifestId;

	/** The list of references to be incorporated into the Manifest */
	private final List<DSSReference> references;

	/** The namespace */
	private final DSSNamespace xmldsigNamespace;
	
	/**
	 * Constructor for the builder (the Id of the Manifest tag will be equals to "manifest")
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param documents
	 *            the documents to include
	 */
	public ManifestBuilder(DigestAlgorithm digestAlgorithm, List<DSSDocument> documents) {
		this(DEFAULT_MANIFEST_ID, digestAlgorithm, documents);
	}

	/**
	 * Constructor for the builder
	 * 
	 * @param manifestId
	 *            the Id of the Manifest tag
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param documents
	 *            the documents to include
	 */
	public ManifestBuilder(final String manifestId, DigestAlgorithm digestAlgorithm, List<DSSDocument> documents) {
		this(manifestId, digestAlgorithm, documents, DEFAULT_NAMESPACE);
	}

	/**
	 * Constructor for the builder
	 * 
	 * @param manifestId
	 *            the Id of the Manifest tag
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param documents
	 *            the documents to include
	 * @param xmldsigNamespace 
	 * 			the xmldsig namespace definition           
	 */
	public ManifestBuilder(final String manifestId, DigestAlgorithm digestAlgorithm, List<DSSDocument> documents,
						   final DSSNamespace xmldsigNamespace) {
		this(manifestId, createReferences(manifestId, digestAlgorithm, documents), xmldsigNamespace);
	}

	/**
	 * The constructor with custom references and default manifest id
	 *
	 * @param references
	 * 			  a list of custom {@link DSSReference}s to be incorporated into the Manifest
	 */
	public ManifestBuilder(final List<DSSReference> references) {
		this(DEFAULT_MANIFEST_ID, references);
	}

	/**
	 * The constructor with custom references and default namespace
	 *
	 * @param manifestId
	 * 			  {@link String} the id of the Manifest element
	 * @param references
	 * 			  a list of custom {@link DSSReference}s to be incorporated into the Manifest
	 */
	public ManifestBuilder(final String manifestId, final List<DSSReference> references) {
		this(manifestId, references, DEFAULT_NAMESPACE);
	}

	/**
	 * The constructor with custom references
	 *
	 * @param manifestId
	 * 			  {@link String} the id of the Manifest element
	 * @param references
	 * 			  a list of custom {@link DSSReference}s to be incorporated into the Manifest
	 * @param xmldsigNamespace
	 * 			  {@link String} the xmldsig namespace definition
	 */
	public ManifestBuilder(final String manifestId, final List<DSSReference> references,
						   final DSSNamespace xmldsigNamespace) {
		if (Utils.isCollectionEmpty(references)) {
			throw new IllegalArgumentException("List of references cannot be empty!");
		}
		this.manifestId = manifestId;
		this.references = references;
		this.xmldsigNamespace = xmldsigNamespace;
	}

	private static List<DSSReference> createReferences(String manifestId, DigestAlgorithm digestAlgorithm,
													   List<DSSDocument> documents) {
		if (Utils.isCollectionEmpty(documents)) {
			throw new IllegalArgumentException("List of documents cannot be empty!");
		}
		ReferenceBuilder referenceBuilder = new ReferenceBuilder(documents, digestAlgorithm);
		referenceBuilder.setReferenceIdPrefix("r-" + manifestId + "-");
		return referenceBuilder.build();
	}

	/**
	 * Builds the Manifest
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument build() {
		Document documentDom = DomUtils.buildDOM();

		Element manifestDom = DomUtils.createElementNS(documentDom, xmldsigNamespace, XMLDSigElement.MANIFEST);
		manifestDom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), manifestId);
		documentDom.appendChild(manifestDom);

		ReferenceProcessor referenceProcessor = new ReferenceProcessor();
		referenceProcessor.incorporateReferences(manifestDom, references, xmldsigNamespace);

		return DomUtils.createDssDocumentFromDomDocument(documentDom, manifestId);
	}

}
