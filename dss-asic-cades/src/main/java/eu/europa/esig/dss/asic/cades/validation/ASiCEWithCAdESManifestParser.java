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
package eu.europa.esig.dss.asic.cades.validation;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCNamespace;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;

public class ASiCEWithCAdESManifestParser {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithCAdESManifestParser.class);

	private final DSSDocument manifestDocument;

	static {
		DomUtils.registerNamespace("asic", ASiCNamespace.NS);
	}

	public ASiCEWithCAdESManifestParser(DSSDocument manifestDocument) {
		this.manifestDocument = manifestDocument;
	}

	public ManifestFile getManifest() {
		ManifestFile manifest = new ManifestFile();
		manifest.setDocument(manifestDocument);

		try (InputStream is = manifestDocument.openStream()) {
			Document manifestDom = DomUtils.buildDOM(is);
			Element root = DomUtils.getElement(manifestDom, ASiCNamespace.ASIC_MANIFEST);

			manifest.setSignatureFilename(DomUtils.getValue(root, ASiCNamespace.SIG_REFERENCE_URI));
			manifest.setEntries(parseManifestEntries(root));

		} catch (Exception e) {
			LOG.warn("Unable to analyze manifest file '{}' : {}", manifestDocument.getName(), e.getMessage());
		}

		return manifest;
	}

	private List<ManifestEntry> parseManifestEntries(Element root) {
		List<ManifestEntry> entries = new ArrayList<ManifestEntry>();
		NodeList dataObjectReferences = DomUtils.getNodeList(root, ASiCNamespace.DATA_OBJECT_REFERENCE);
		if (dataObjectReferences == null || dataObjectReferences.getLength() == 0) {
			LOG.warn("No DataObjectReference found in manifest file");
		} else {
			for (int i = 0; i < dataObjectReferences.getLength(); i++) {
				ManifestEntry entry = new ManifestEntry();
				Element dataObjectReference = (Element) dataObjectReferences.item(i);
				entry.setFileName(dataObjectReference.getAttribute(ASiCNamespace.DATA_OBJECT_REFERENCE_URI));
				
				MimeType mimeType = MimeType.fromMimeTypeString(dataObjectReference.getAttribute(ASiCNamespace.DATA_OBJECT_REFERENCE_MIMETYPE));
				if (mimeType != null) {
					entry.setMimeType(mimeType);
				}

				DigestAlgorithm digestAlgorithm = null;
				byte[] digestValueBinary = null;
				
				// Loop over child nodes because in order to ignore namespace
				// TODO: resolve namespace issue
				if (dataObjectReference.hasChildNodes()) {
					NodeList childNodes = dataObjectReference.getChildNodes();
					for (int ii = 0; ii < childNodes.getLength(); ii++) {
						Node child = childNodes.item(ii);
						if (ASiCNamespace.DIGEST_METHOD.equals(child.getLocalName())) {
							digestAlgorithm = DigestAlgorithm.forXML(((Element)child).getAttribute(ASiCNamespace.DIGEST_METHOD_ALGORITHM));
						} else if (ASiCNamespace.DIGEST_VALUE.equals(child.getLocalName())) {
							digestValueBinary = Utils.fromBase64(child.getTextContent());
						}
					}
				}
				
				if (digestAlgorithm != null && digestValueBinary != null) {
					entry.setDigest(new Digest(digestAlgorithm, digestValueBinary));
				}
				
				entries.add(entry);
			}
		}
		return entries;
	}

}
