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
package eu.europa.esig.dss.asic.signature.asice;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.asic.ASiCNamespace;

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

	private final List<DSSDocument> signatures;
	private final List<DSSDocument> documents;
	private final List<DSSDocument> manifests;
	private final DigestAlgorithm digestAlgorithm;
	private final String timestampUri;

	public ASiCEWithCAdESArchiveManifestBuilder(List<DSSDocument> signatures, List<DSSDocument> documents, List<DSSDocument> manifests,
			DigestAlgorithm digestAlgorithm, String timestampUri) {
		this.signatures = signatures;
		this.documents = documents;
		this.manifests = manifests;
		this.digestAlgorithm = digestAlgorithm;
		this.timestampUri = timestampUri;
	}

	public Document build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element asicManifestDom = documentDom.createElementNS(ASiCNamespace.NS, ASiCNamespace.ASIC_MANIFEST);
		documentDom.appendChild(asicManifestDom);

		addSigReference(documentDom, asicManifestDom, timestampUri, MimeType.TST);

		for (DSSDocument signature : signatures) {
			addDataObjectReference(documentDom, asicManifestDom, signature, digestAlgorithm);
		}

		for (DSSDocument document : documents) {
			addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		}

		for (DSSDocument manifest : manifests) {
			addDataObjectReference(documentDom, asicManifestDom, manifest, digestAlgorithm);
		}

		return documentDom;
	}

}
