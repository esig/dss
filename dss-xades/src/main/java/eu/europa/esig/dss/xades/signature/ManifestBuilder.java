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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

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

	/** The manifest id */
	private final String manifestId;

	/** The DigestAlgorithm to use */
	private final DigestAlgorithm digestAlgorithm;

	/** List of manifested documents */
	private final List<DSSDocument> documents;

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
		this("manifest", digestAlgorithm, documents);
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
	public ManifestBuilder(String manifestId, DigestAlgorithm digestAlgorithm, List<DSSDocument> documents) {
		this(manifestId, digestAlgorithm, documents, new DSSNamespace("http://www.w3.org/2000/09/xmldsig#", "ds"));
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
	public ManifestBuilder(String manifestId, DigestAlgorithm digestAlgorithm, List<DSSDocument> documents, DSSNamespace xmldsigNamespace) {
		this.manifestId = manifestId;
		this.digestAlgorithm = digestAlgorithm;
		this.documents = documents;
		this.xmldsigNamespace = xmldsigNamespace;
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

		for (DSSDocument document : documents) {

			Element referenceDom = DomUtils.createElementNS(documentDom, xmldsigNamespace, XMLDSigElement.REFERENCE);
			manifestDom.appendChild(referenceDom);
			referenceDom.setAttribute(XMLDSigAttribute.URI.getAttributeName(), document.getName());

			Element digestMethodDom = DomUtils.createElementNS(documentDom, xmldsigNamespace, XMLDSigElement.DIGEST_METHOD);
			referenceDom.appendChild(digestMethodDom);
			digestMethodDom.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), digestAlgorithm.getUri());

			Element digestValueDom = DomUtils.createElementNS(documentDom, xmldsigNamespace, XMLDSigElement.DIGEST_VALUE);
			referenceDom.appendChild(digestValueDom);
			Text textNode = documentDom.createTextNode(document.getDigest(digestAlgorithm));
			digestValueDom.appendChild(textNode);

		}

		return DomUtils.createDssDocumentFromDomDocument(documentDom, manifestId);
	}

}
