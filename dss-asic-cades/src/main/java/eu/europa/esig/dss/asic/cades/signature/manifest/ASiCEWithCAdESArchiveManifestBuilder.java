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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.definition.ASiCAttribute;
import eu.europa.esig.dss.asic.common.definition.ASiCElement;
import eu.europa.esig.dss.asic.common.definition.ASiCNamespace;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.List;

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

	/** The list of signature documents */
	private final List<DSSDocument> signatures;

	/** The list of timestamp documents */
	private final List<DSSDocument> timestamps;

	/** The list of signed documents */
	private final List<DSSDocument> signedFiles;

	/** The list of manifests */
	private final List<DSSDocument> manifests;

	/** The "ASiCArchiveManifest.xml" document (root manifest) */
	private final DSSDocument lastArchiveManifest;

	/** The DigestAlgorithm to use for reference digests computation */
	private final DigestAlgorithm digestAlgorithm;

	/** The name of the timestamp document */
	private final String timestampFileUri;

	/**
	 * The default constructor
	 *
	 * @param signatures a list of {@link DSSDocument} signatures
	 * @param timestamps a list of {@link DSSDocument} timestamps
	 * @param signedFiles a list of {@link DSSDocument} signed files
	 * @param manifests a list of {@link DSSDocument} manifests
	 * @param lastArchiveManifets {@link DSSDocument} the last archive manifest "ASiCArchiveManifest.xml"
	 * @param digestAlgorithm {@link DigestAlgorithm} to use for digest calculation
	 * @param timestampFileUri {@link String} the name of the timestamp to add
	 */
	public ASiCEWithCAdESArchiveManifestBuilder(List<DSSDocument> signatures, List<DSSDocument> timestamps, List<DSSDocument> signedFiles,
			List<DSSDocument> manifests, DSSDocument lastArchiveManifets, DigestAlgorithm digestAlgorithm, String timestampFileUri) {
		this.signatures = signatures;
		this.timestamps = timestamps;
		this.signedFiles = signedFiles;
		this.manifests = manifests;
		this.lastArchiveManifest = lastArchiveManifets;
		this.digestAlgorithm = digestAlgorithm;
		this.timestampFileUri = timestampFileUri;
	}

	/**
	 * Builds the ArchiveManifest and returns the Document Node
	 *
	 * @return {@link Document} archive manifest
	 */
	public Document build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element asicManifestDom = DomUtils.createElementNS(documentDom, ASiCNamespace.NS, ASiCElement.ASIC_MANIFEST);
		documentDom.appendChild(asicManifestDom);

		addSigReference(documentDom, asicManifestDom, timestampFileUri, MimeType.TST);

		for (DSSDocument signature : signatures) {
			addDataObjectReference(documentDom, asicManifestDom, signature, digestAlgorithm);
		}
		
		for (DSSDocument timestamp : timestamps) {
			addDataObjectReference(documentDom, asicManifestDom, timestamp, digestAlgorithm);
		}

		for (DSSDocument manifest : manifests) {
			addDataObjectReference(documentDom, asicManifestDom, manifest, digestAlgorithm);
		}
		
		if (lastArchiveManifest != null) {
			addDataObjectReferenceForRootArchiveManifest(documentDom, asicManifestDom, lastArchiveManifest, digestAlgorithm);
		}

		for (DSSDocument document : signedFiles) {
			addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		}

		return documentDom;
	}
	
	private Element addDataObjectReferenceForRootArchiveManifest(final Document documentDom, final Element asicManifestDom, 
			DSSDocument document, DigestAlgorithm digestAlgorithm) {
		Element dataObjectReferenceElement = addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		dataObjectReferenceElement.setAttribute(ASiCAttribute.ROOTFILE.getAttributeName(), "true");
		return dataObjectReferenceElement;
	}

}
