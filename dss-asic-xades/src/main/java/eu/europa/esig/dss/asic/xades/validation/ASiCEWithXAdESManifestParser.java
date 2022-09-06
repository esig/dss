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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.xades.definition.ManifestNamespace;
import eu.europa.esig.dss.asic.xades.definition.ManifestPaths;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class parses the ASiC with XAdES manifest document and produces a {@code ManifestFile}
 */
public class ASiCEWithXAdESManifestParser {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithXAdESManifestParser.class);

	static {
		DomUtils.registerNamespace(ManifestNamespace.NS);
	}

	/** The related signature document */
	private final DSSDocument signatureDocument;

	/** The manifest document to be parsed */
	private final DSSDocument manifestDocument;

	/**
	 * Constructor with a manifest document only (no assigned signature)
	 *
	 * @param manifestDocument {@link DSSDocument} to be parsed
	 */
	public ASiCEWithXAdESManifestParser(DSSDocument manifestDocument) {
		this(null, manifestDocument);
	}

	/**
	 * The default constructor
	 *
	 * @param signatureDocument {@link DSSDocument} the linked signature
	 * @param manifestDocument {@link DSSDocument} to be parsed
	 */
	public ASiCEWithXAdESManifestParser(DSSDocument signatureDocument, DSSDocument manifestDocument) {
		this.signatureDocument = signatureDocument;
		this.manifestDocument = manifestDocument;
	}

	/**
	 * Returns a parsed {@code ManifestFile}
	 *
	 * @return {@link ManifestFile}
	 */
	public ManifestFile getManifest() {
		ManifestFile manifest = new ManifestFile();
		manifest.setDocument(manifestDocument);
		if (signatureDocument != null) {
			manifest.setSignatureFilename(signatureDocument.getName());
		}
		manifest.setEntries(getEntries());
		return manifest;
	}

	private List<ManifestEntry> getEntries() {
		if (!DomUtils.isDOM(manifestDocument)) {
			LOG.warn("Unable to parse manifest file '{}': the document is not a valid XML!", manifestDocument.getName());
			return Collections.emptyList();
		}

		List<ManifestEntry> result = new ArrayList<>();
		try {
			Document manifestDom = DomUtils.buildDOM(manifestDocument);
			DSSNamespace manifestNamespace = getManifestNamespace(manifestDom);
			DomUtils.registerNamespace(manifestNamespace);

			NodeList nodeList = DomUtils.getNodeList(manifestDom, ManifestPaths.FILE_ENTRY_PATH);
			if (nodeList != null && nodeList.getLength() > 0) {
				for (int i = 0; i < nodeList.getLength(); i++) {
					ManifestEntry manifestEntry = new ManifestEntry();
					Element fileEntryElement = (Element) nodeList.item(i);
					String fullpathValue = fileEntryElement.getAttribute(ManifestPaths.getFullPathAttribute(manifestNamespace));
					if (!isFolder(fullpathValue)) {
						manifestEntry.setFileName(fullpathValue);
						manifestEntry.setMimeType(getMimeType(fileEntryElement, manifestNamespace));
						result.add(manifestEntry);
					}
				}
			}

		} catch (Exception e) {
			String errorMessage = "Unable to parse manifest file '{}' : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, manifestDocument.getName(), e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, manifestDocument.getName(), e.getMessage());
			}
		}
		return result;
	}

	private DSSNamespace getManifestNamespace(Document manifestDom) {
		DSSNamespace manifestNamespace = DomUtils.browseRecursivelyForNamespaceWithUri(
				manifestDom.getDocumentElement(), ManifestNamespace.NS.getUri());
		return manifestNamespace != null ? manifestNamespace : ManifestNamespace.NS;
	}

	private MimeType getMimeType(Element fileEntryElement, DSSNamespace manifestNamespace) {
		String mediaType = fileEntryElement.getAttribute(ManifestPaths.getMediaTypeAttribute(manifestNamespace));
		if (Utils.isStringNotBlank(mediaType)) {
			return MimeType.fromMimeTypeString(mediaType);
		}
		return null;
	}

	private boolean isFolder(String fullpathValue) {
		return fullpathValue.endsWith("/");
	}

}
