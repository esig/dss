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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.definition.ManifestAttribute;
import eu.europa.esig.dss.asic.xades.definition.ManifestElement;
import eu.europa.esig.dss.asic.xades.definition.ManifestNamespace;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.List;

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

	/** List of documents to be included into the manifest */
	private List<DSSDocument> documents;

	/** List of manifest entries to be included into the manifest */
	private List<ManifestEntry> entries;

	/** The name of the created manifest document */
	private String manifestFilename;

	/**
	 * Empty constructor
	 */
	public ASiCEWithXAdESManifestBuilder() {
		// empty
	}

	/**
	 * Sets documents to be included into the Manifest
	 *
	 * WARN: shall not be used together with {@code setEntries(entries)}
	 *
	 * @param documents list of {@link DSSDocument}s
	 * @return this {@link ASiCEWithXAdESManifestBuilder}
	 */
	public ASiCEWithXAdESManifestBuilder setDocuments(List<DSSDocument> documents) {
		this.documents = documents;
		return this;
	}

	/**
	 * Sets manifest entries to be included into the Manifest
	 *
	 * WARN: shall not be used together with {@code setDocuments(documents)}
	 *
	 * @param entries list of {@link ManifestEntry}s
	 * @return this {@link ASiCEWithXAdESManifestBuilder}
	 */
	public ASiCEWithXAdESManifestBuilder setEntries(List<ManifestEntry> entries) {
		this.entries = entries;
		return this;
	}

	/**
	 * Sets the target name of the XML Manifest file to be created
	 *
	 * @param manifestFilename {@link String}
	 * @return this {@link ASiCEWithXAdESManifestBuilder}
	 */
	public ASiCEWithXAdESManifestBuilder setManifestFilename(String manifestFilename) {
		this.manifestFilename = manifestFilename;
		return this;
	}

	/**
	 * Builds the XML manifest
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element manifestDom = DomUtils.createElementNS(documentDom, ManifestNamespace.NS, ManifestElement.MANIFEST);
		DomUtils.setAttributeNS(manifestDom, ManifestNamespace.NS, ManifestAttribute.VERSION, "1.2");
		documentDom.appendChild(manifestDom);

		final Element rootDom = DomUtils.addElement(documentDom, manifestDom, ManifestNamespace.NS, ManifestElement.FILE_ENTRY);
		DomUtils.setAttributeNS(rootDom, ManifestNamespace.NS, ManifestAttribute.FULL_PATH, "/");
		DomUtils.setAttributeNS(rootDom, ManifestNamespace.NS, ManifestAttribute.MEDIA_TYPE, MimeTypeEnum.ASICE.getMimeTypeString());

		for (ManifestEntry entry : getEntries()) {
			Element fileDom = DomUtils.addElement(documentDom, manifestDom, ManifestNamespace.NS, ManifestElement.FILE_ENTRY);
			DomUtils.setAttributeNS(fileDom, ManifestNamespace.NS, ManifestAttribute.FULL_PATH, entry.getFileName());
			MimeType mimeType = entry.getMimeType();
			if (mimeType != null) {
				DomUtils.setAttributeNS(fileDom, ManifestNamespace.NS, ManifestAttribute.MEDIA_TYPE, mimeType.getMimeTypeString());
			}
		}

		return DomUtils.createDssDocumentFromDomDocument(documentDom, manifestFilename);
	}

	private List<ManifestEntry> getEntries() {
		if (Utils.isCollectionNotEmpty(documents) && Utils.isCollectionNotEmpty(entries)) {
			throw new IllegalArgumentException("Either DSSDocuments or ManifestEntries shall be provided!");
		} else if (Utils.isCollectionNotEmpty(documents)) {
			return ASiCUtils.toSimpleManifestEntries(documents);
		} else if (Utils.isCollectionNotEmpty(entries)) {
			return entries;
		} else {
			throw new NullPointerException("Either DSSDocuments or ManifestEntries shall be provided!");
		}
	}

}
