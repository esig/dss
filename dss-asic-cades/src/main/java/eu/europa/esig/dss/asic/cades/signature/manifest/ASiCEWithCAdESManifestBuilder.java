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
package eu.europa.esig.dss.asic.cades.signature.manifest;

import eu.europa.esig.asic.manifest.definition.ASiCManifestElement;
import eu.europa.esig.asic.manifest.definition.ASiCManifestNamespace;
import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class is used to generate the ASiCManifest.xml content (ASiC-E)
 *
 * Sample:
 * 
 * <pre>
 * {@code
 * 		<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">
 *			<asic:SigReference MimeType="application/pkcs7-signature" URI="META-INF/signature001.p7s">
 *				<asic:DataObjectReference URI="document.txt">
 *					<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm=
"http://www.w3.org/2001/04/xmlenc#sha256"/>
 *					<DigestValue xmlns=
"http://www.w3.org/2000/09/xmldsig#">OuL0HMJE899y+uJtyNnTt5B/gFrrw8adNczI+9w9GDQ=</DigestValue>
 *				</asic:DataObjectReference>
 *			</asic:SigReference>
 *		</asic:ASiCManifest>
 * }
 * </pre>
 */
public abstract class ASiCEWithCAdESManifestBuilder extends AbstractManifestBuilder {

	/** The container representation */
	private final ASiCContent asicContent;

	/** The DigestAlgorithm to use for reference digests computation */
	private final DigestAlgorithm digestAlgorithm;

	/** The URI of a document signing the manifest */
	private final String documentUri;

	/**
	 * Defines rules for filename creation for new manifest files.
	 */
	private final ASiCWithCAdESFilenameFactory asicFilenameFactory;

	/**
	 * The default constructor
	 *
	 * @param asicContent {@link ASiCContent} representing container's document structure
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for reference digest computation
	 * @param documentUri {@link String} filename of the document associated with the manifest
	 */
	protected ASiCEWithCAdESManifestBuilder(final ASiCContent asicContent, final DigestAlgorithm digestAlgorithm,
											final String documentUri) {
		this(asicContent, digestAlgorithm, documentUri, new DefaultASiCWithCAdESFilenameFactory());
	}

	/**
	 * Constructor with filename factory
	 *
	 * @param asicContent {@link ASiCContent} representing container's document structure
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for reference digest computation
	 * @param documentUri {@link String} filename of the document associated with the manifest
	 * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
	 */
	protected ASiCEWithCAdESManifestBuilder(final ASiCContent asicContent, final DigestAlgorithm digestAlgorithm,
											final String documentUri, final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
		this.asicContent = asicContent;
		this.digestAlgorithm = digestAlgorithm;
		this.documentUri = documentUri;
		this.asicFilenameFactory = asicFilenameFactory;
	}

	/**
	 * Builds the manifest and returns the document
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element asicManifestDom = DomUtils.createElementNS(documentDom, ASiCManifestNamespace.NS, ASiCManifestElement.ASIC_MANIFEST);
		documentDom.appendChild(asicManifestDom);

		addSigReference(documentDom, asicManifestDom, documentUri, getSigReferenceMimeType());

		for (DSSDocument document : asicContent.getSignedDocuments()) {
			addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		}

		String newManifestName = asicFilenameFactory.getManifestFilename(asicContent);
		return DomUtils.createDssDocumentFromDomDocument(documentDom, newManifestName);
	}

	/**
	 * Returns the {@code MimeType} to be used for a signature reference (signature or timestamp)
	 *
	 * @return {@link MimeType}
	 */
	protected abstract MimeType getSigReferenceMimeType();

}
