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
package eu.europa.esig.dss.asic.xades.signature.asice;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.xades.ManifestNamespace;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;

/**
 * This class is used to build the manifest.xml file (ASiC-E).
 * 
 * Sample:
 * 
 * <pre>
 * {@code
 * 		<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
 * 			<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>
 * 			<manifest:file-entry manifest:full-path="test.txt" manifest:media-type="text/plain"/>
 * 			<manifest:file-entry manifest:full-path="test-data-file.bin" manifest:media-type=
"application/octet-stream"/>
 * 		</manifest:manifest>
 * }
 * </pre>
 *
 */
public class ASiCEWithXAdESManifestBuilder {

	private final List<DSSDocument> documents;

	public ASiCEWithXAdESManifestBuilder(List<DSSDocument> documents) {
		this.documents = documents;
	}

	public Document build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element manifestDom = documentDom.createElementNS(ManifestNamespace.NS, ManifestNamespace.MANIFEST);
		manifestDom.setAttributeNS(ManifestNamespace.NS, ManifestNamespace.VERSION, "1.2");
		documentDom.appendChild(manifestDom);

		final Element rootDom = DomUtils.addElement(documentDom, manifestDom, ManifestNamespace.NS, ManifestNamespace.FILE_ENTRY);
		rootDom.setAttributeNS(ManifestNamespace.NS, ManifestNamespace.FULL_PATH, "/");
		rootDom.setAttributeNS(ManifestNamespace.NS, ManifestNamespace.MEDIA_TYPE, MimeType.ASICE.getMimeTypeString());

		for (DSSDocument document : documents) {
			Element fileDom = DomUtils.addElement(documentDom, manifestDom, ManifestNamespace.NS, ManifestNamespace.FILE_ENTRY);
			fileDom.setAttributeNS(ManifestNamespace.NS, ManifestNamespace.FULL_PATH, document.getName());
			MimeType mimeType = document.getMimeType();
			if (mimeType != null) {
				fileDom.setAttributeNS(ManifestNamespace.NS, ManifestNamespace.MEDIA_TYPE, mimeType.getMimeTypeString());
			}
		}

		return documentDom;
	}

}
