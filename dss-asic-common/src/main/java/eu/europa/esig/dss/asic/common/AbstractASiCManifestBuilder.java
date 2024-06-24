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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.asic.common.definition.ASiCManifestAttribute;
import eu.europa.esig.dss.asic.common.definition.ASiCManifestElement;
import eu.europa.esig.dss.asic.common.definition.ASiCManifestNamespace;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilter;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import java.util.Objects;

/**
 * The abstract class to build a Manifest for ASiC
 */
public abstract class AbstractASiCManifestBuilder {

	/** The container representation */
	protected final ASiCContent asicContent;

	/** The URI of a document signing the manifest */
	protected final String sigReferenceUri;

	/** The DigestAlgorithm to use for reference digests computation */
	protected final DigestAlgorithm digestAlgorithm;

	/** This object is used to filter the documents to compute hashes for */
	private ASiCContentDocumentFilter asicContentDocumentFilter;

	/**
	 * Constructor to instantiate AbstractASiCManifestBuilder with a default SHA-256 digest algorithm
	 */
	protected AbstractASiCManifestBuilder(final ASiCContent asicContent, final String sigReferenceUri) {
		this(asicContent, sigReferenceUri, DigestAlgorithm.SHA256);
	}

	/**
	 * Constructor to instantiate AbstractASiCManifestBuilder with a provided digest algorithm
	 *
	 * @param asicContent {@link ASiCContent} representing the structure of the ASiC container
	 * @param sigReferenceUri {@link String} name of the document to be linked to the manifest (e.g. name of the signature file)
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used for digest computation of DataObjectReference's
	 */
	protected AbstractASiCManifestBuilder(final ASiCContent asicContent, final String sigReferenceUri,
										  final DigestAlgorithm digestAlgorithm) {
		this.asicContent = asicContent;
		this.sigReferenceUri = sigReferenceUri;
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * Builds the ArchiveManifest and returns the Document Node
	 *
	 * @return {@link DSSDocument} archive manifest
	 */
	public DSSDocument build() {
		final Document documentDom = buildDom();
		final Element asicManifestDom = createRootElement(documentDom);

		addSigReference(documentDom, asicManifestDom);
		addDataObjectReferences(documentDom, asicManifestDom);

		return toDSSDocument(documentDom);
	}

	/**
	 * Builds the initial XML document
	 *
	 * @return {@link Document}
	 */
	protected Document buildDom() {
		return DomUtils.buildDOM();
	}

	/**
	 * Creates a root element {@code <asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">}
	 *
	 * @param documentDom {@link Document}
	 * @return {@link  Element}
	 */
	protected Element createRootElement(Document documentDom) {
		final Element asicManifestDom = DomUtils.createElementNS(documentDom, ASiCManifestNamespace.NS, ASiCManifestElement.ASIC_MANIFEST);
		documentDom.appendChild(asicManifestDom);
		return asicManifestDom;
	}

	/**
	 * Adds a {@code <SigReference>} element
	 *
	 * @param documentDom {@link Document} to add the SigReference to
	 * @param asicManifestDom {@link Element} containing an asicManifestDom to incorporate the SigReference within
	 */
	protected void addSigReference(final Document documentDom, final Element asicManifestDom) {
		final Element sigReferenceDom = DomUtils.addElement(documentDom, asicManifestDom, ASiCManifestNamespace.NS, ASiCManifestElement.SIG_REFERENCE);
		sigReferenceDom.setAttribute(ASiCManifestAttribute.URI.getAttributeName(), DSSUtils.encodeURI(sigReferenceUri));
		MimeType sigReferenceMimeType = getSigReferenceMimeType();
		if (sigReferenceMimeType != null) {
			sigReferenceDom.setAttribute(ASiCManifestAttribute.MIME_TYPE.getAttributeName(), sigReferenceMimeType.getMimeTypeString());
		}
	}

	/**
	 * (Optional) Returns the {@code MimeType} to be used for a signature reference (signature or timestamp)
	 *
	 * @return {@link MimeType}
	 */
	protected abstract MimeType getSigReferenceMimeType();

	/**
	 * This method adds references to data objects, corresponding to the {@code ASiCContentDocumentFilter} configuration
	 *
	 * @param documentDom {@link Document}
	 * @param asicManifestDom {@link Element} the root element to add the references to
	 */
	protected void addDataObjectReferences(final Document documentDom, final Element asicManifestDom) {
		ASiCContentDocumentFilter documentFilter = getAsicContentDocumentFilter();
		Objects.requireNonNull(documentFilter, "ASiCContentDocumentFilter cannot be null!");

		for (DSSDocument document : documentFilter.filter(asicContent)) {
			addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		}
	}

	/**
	 * Gets an {@code ASiCContentDocumentFilter} used to filter the documents to be referenced within ASiC Manifest
	 *
	 * @return {@link ASiCContentDocumentFilter}
	 */
	protected ASiCContentDocumentFilter getAsicContentDocumentFilter() {
		if (asicContentDocumentFilter == null) {
			asicContentDocumentFilter = initDefaultAsicContentDocumentFilter();
		}
		return asicContentDocumentFilter;
	}

	/**
	 * Sets an {@code ASiCContentDocumentFilter} used to filter the documents to compute hashes for.
	 * When not set, a default {@code ASiCContentDocumentFilter} is used for the given manifest type.
	 *
	 * @param asicContentDocumentFilter {@link ASiCContentDocumentFilter}
	 * @return this {@link ASiCEvidenceRecordDigestBuilder}
	 */
	public AbstractASiCManifestBuilder setAsicContentDocumentFilter(ASiCContentDocumentFilter asicContentDocumentFilter) {
		this.asicContentDocumentFilter = asicContentDocumentFilter;
		return this;
	}

	/**
	 * Gets an {@code ASiCContentDocumentFilter} used to filter the documents to be referenced within ASiC Manifest
	 *
	 * @return {@link ASiCContentDocumentFilter}
	 */
	protected abstract ASiCContentDocumentFilter initDefaultAsicContentDocumentFilter();

	/**
	 * Adds a {@code <DataObjectReference>} element
	 *
	 * @param documentDom {@link Document} to add the DataObjectReference to
	 * @param asicManifestDom {@link Element} containing an asicManifestDom to incorporate
	 *                                          the DataObjectReference within
	 * @param document {@link DSSDocument} to refer
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for digest calculation
	 * @return {@link Element}
	 */
	protected Element addDataObjectReference(final Document documentDom, final Element asicManifestDom,
											 DSSDocument document, DigestAlgorithm digestAlgorithm) {
		final Element dataObjectReferenceDom = DomUtils.addElement(documentDom, asicManifestDom, ASiCManifestNamespace.NS, ASiCManifestElement.DATA_OBJECT_REFERENCE);
		
		dataObjectReferenceDom.setAttribute(ASiCManifestAttribute.URI.getAttributeName(), DSSUtils.encodeURI(document.getName()));

		MimeType mimeType = document.getMimeType();
		if (mimeType != null) {
			dataObjectReferenceDom.setAttribute(ASiCManifestAttribute.MIME_TYPE.getAttributeName(), mimeType.getMimeTypeString());
		}

		if (isRootfile(document)) {
			dataObjectReferenceDom.setAttribute(ASiCManifestAttribute.ROOTFILE.getAttributeName(), "true");
		}

		final Element digestMethodDom = DomUtils.addElement(documentDom, dataObjectReferenceDom, XMLDSigNamespace.NS, XMLDSigElement.DIGEST_METHOD);
		digestMethodDom.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), digestAlgorithm.getUri());

		final Element digestValueDom = DomUtils.addElement(documentDom, dataObjectReferenceDom, XMLDSigNamespace.NS, XMLDSigElement.DIGEST_VALUE);
		final Text textNode = documentDom.createTextNode(Utils.toBase64(document.getDigestValue(digestAlgorithm)));
		digestValueDom.appendChild(textNode);
		
		return dataObjectReferenceDom;
	}

	/**
	 * Specifies whether the {@code document} is a Rootfile document
	 *
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the Rootfile attribute shall be added for the document's reference, FALSE otherwise
	 */
	protected boolean isRootfile(DSSDocument document) {
		// FALSE by default
		return false;
	}

	/**
	 * Transforms {@code Document} to {@code DSSDocument}
	 *
	 * @param documentDom {@link Document}
	 * @return {@link DSSDocument}
	 */
	protected DSSDocument toDSSDocument(Document documentDom) {
		String newManifestName = getManifestFilename();
		return DomUtils.createDssDocumentFromDomDocument(documentDom, newManifestName);
	}

	/**
	 * Returns a final filename of the manifest
	 *
	 * @return {@link String}
	 */
	protected abstract String getManifestFilename();

}
