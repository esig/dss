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

import eu.europa.esig.asic.manifest.definition.ASiCManifestAttribute;
import eu.europa.esig.asic.manifest.definition.ASiCManifestElement;
import eu.europa.esig.asic.manifest.definition.ASiCManifestNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class is used to generate the ASiCArchiveManifest.xml content (ASiC-E)
 *
 * Sample:
 * 
 * <pre>
 * {@code
 * 		<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">
 *			<asic:SigReference URI="META-INF/archive_timestamp.tst" MimeType="application/vnd.etsi.timestamp-token"/>
 *			<asic:DataObjectReference URI="META-INF/signature.p7s" MimeType="application/x-pkcs7-signature">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *				<DigestValue>3Qeos8...</DigestValue>
 *			</asic:DataObjectReference>
 *			<asic:DataObjectReference URI="toBeSigned.txt" MimeType="text/plain">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/> 
 *				<DigestValue>JJZt...</DigestValue>
 *			</asic:DataObjectReference>
 *			<asic:DataObjectReference URI="META-INF/ASiCManifest_1.xml" MimeType="text/xml">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *				<DigestValue>g5dY...</DigestValue>
 *			</asic:DataObjectReference>
 * 		</asic:ASiCManifest>
 * }
 * </pre>
 */
public class ASiCEWithCAdESArchiveManifestBuilder extends AbstractManifestBuilder {

	/** The ASiC Container document representation */
	private final ASiCContent asicContent;

	/** The "ASiCArchiveManifest.xml" document (root manifest) */
	private final DSSDocument lastArchiveManifest;

	/** The DigestAlgorithm to use for reference digests computation */
	private final DigestAlgorithm digestAlgorithm;

	/** The name of the timestamp document */
	private final String timestampFileUri;

	/**
	 * The default constructor
	 *
	 * @param asicContent {@link ASiCContent}
	 * @param lastArchiveManifest {@link DSSDocument} the last archive manifest "ASiCArchiveManifest.xml"
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for digest calculation
	 * @param timestampFileUri {@link String} the name of the timestamp to add
	 */
	public ASiCEWithCAdESArchiveManifestBuilder(ASiCContent asicContent, DSSDocument lastArchiveManifest,
												DigestAlgorithm digestAlgorithm, String timestampFileUri) {
		this.asicContent = asicContent;
		this.lastArchiveManifest = lastArchiveManifest;
		this.digestAlgorithm = digestAlgorithm;
		this.timestampFileUri = timestampFileUri;
	}

	/**
	 * Builds the ArchiveManifest and returns the Document Node
	 *
	 * @return {@link DSSDocument} archive manifest
	 */
	public DSSDocument build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element asicManifestDom = DomUtils.createElementNS(documentDom, ASiCManifestNamespace.NS, ASiCManifestElement.ASIC_MANIFEST);
		documentDom.appendChild(asicManifestDom);

		addSigReference(documentDom, asicManifestDom, timestampFileUri, MimeTypeEnum.TST);

		for (DSSDocument signature : asicContent.getSignatureDocuments()) {
			addDataObjectReference(documentDom, asicManifestDom, signature, digestAlgorithm);
		}
		
		for (DSSDocument timestamp : asicContent.getTimestampDocuments()) {
			addDataObjectReference(documentDom, asicManifestDom, timestamp, digestAlgorithm);
		}

		for (DSSDocument manifest : asicContent.getAllManifestDocuments()) {
			if (lastArchiveManifest == manifest) {
				addDataObjectReferenceForRootArchiveManifest(documentDom, asicManifestDom, lastArchiveManifest, digestAlgorithm);
			} else {
				addDataObjectReference(documentDom, asicManifestDom, manifest, digestAlgorithm);
			}
		}

		for (DSSDocument document : asicContent.getSignedDocuments()) {
			addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		}

		return DomUtils.createDssDocumentFromDomDocument(documentDom, ASiCWithCAdESUtils.DEFAULT_ARCHIVE_MANIFEST_FILENAME);
	}
	
	private Element addDataObjectReferenceForRootArchiveManifest(final Document documentDom, final Element asicManifestDom, 
			DSSDocument document, DigestAlgorithm digestAlgorithm) {
		Element dataObjectReferenceElement = addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		dataObjectReferenceElement.setAttribute(ASiCManifestAttribute.ROOTFILE.getAttributeName(), "true");
		return dataObjectReferenceElement;
	}

}
