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

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.definition.ASiCElement;
import eu.europa.esig.dss.asic.common.definition.ASiCNamespace;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.SigningOperation;

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
public class ASiCEWithCAdESManifestBuilder extends AbstractManifestBuilder {

	private final SigningOperation operation;
	private final List<DSSDocument> documents;
	private final DigestAlgorithm digestAlgorithm;
	private final String uri;

	public ASiCEWithCAdESManifestBuilder(SigningOperation operation, List<DSSDocument> documents, DigestAlgorithm digestAlgorithm, String uri) {
		this.operation = operation;
		this.documents = documents;
		this.digestAlgorithm = digestAlgorithm;
		this.uri = uri;
	}

	public Document build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element asicManifestDom = DomUtils.createElementNS(documentDom, ASiCNamespace.NS, ASiCElement.ASIC_MANIFEST);
		documentDom.appendChild(asicManifestDom);

		if (SigningOperation.SIGN == operation) {
			addSigReference(documentDom, asicManifestDom, uri, MimeType.PKCS7);
		} else {
			addSigReference(documentDom, asicManifestDom, uri, MimeType.TST);
		}

		for (DSSDocument document : documents) {
			addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		}

		return documentDom;
	}

}
