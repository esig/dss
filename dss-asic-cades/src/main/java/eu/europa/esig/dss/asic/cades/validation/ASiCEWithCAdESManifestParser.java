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
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCNamespace;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;

public class ASiCEWithCAdESManifestParser {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithCAdESManifestParser.class);

	static {
		DomUtils.registerNamespace("asic", ASiCNamespace.ASIC_NS);
	}

	/**
	 * Parses and converts {@code DSSDocument} to {@code ManifestFile}
	 * @param manifestDocument {@link DSSDocument} to parse
	 * @return {@link ManifestFile}
	 */
	public static ManifestFile getManifestFile(DSSDocument manifestDocument) {
		Element root = getManifestRootElement(manifestDocument);
		if (root == null) {
			return null;
		}
		ManifestFile manifest = new ManifestFile();
		manifest.setDocument(manifestDocument);
		manifest.setSignatureFilename(getLinkedSignatureName(root));
		manifest.setEntries(parseManifestEntries(root));
		manifest.setArchiveManifest(ASiCUtils.isArchiveManifest(manifestDocument.getName()));
		return manifest;
	}
	
	/**
	 * Returns the relative manifests for the given signature name 
	 * @param manifestDocuments list of found manifests {@link DSSDocument} in the container (candidates)
	 * @param signatureName {@link String} name of the signature to get related manifest for
	 * @return {@link DSSDocument} the related manifests
	 */
	public static DSSDocument getLinkedManifest(List<DSSDocument> manifestDocuments, String signatureName) {
		for (DSSDocument manifest : manifestDocuments) {
			Element manifestRoot = getManifestRootElement(manifest);
			if (manifestRoot != null) {
				String linkedSignatureName = getLinkedSignatureName(manifestRoot);
				if (signatureName.equals(linkedSignatureName)) {
					return manifest;
				}
			}
		}
		return null;
	}
	
	private static Element getManifestRootElement(DSSDocument manifestDocument) {
		try (InputStream is = manifestDocument.openStream()) {
			Document manifestDom = DomUtils.buildDOM(is);
			return DomUtils.getElement(manifestDom, ASiCNamespace.ASIC_MANIFEST);
		} catch (Exception e) {
			LOG.warn("Unable to analyze manifest file '{}' : {}", manifestDocument.getName(), e.getMessage());
			return null;
		}
	}
	
	private static String getLinkedSignatureName(Element root) {
		return DomUtils.getValue(root, ASiCNamespace.SIG_REFERENCE_URI);
	}
	
	private static MimeType getMimeType(Element dataObjectReference) {
		try {
			return MimeType.fromMimeTypeString(dataObjectReference.getAttribute(ASiCNamespace.DATA_OBJECT_REFERENCE_MIMETYPE));
		} catch (DSSException e) {
			LOG.warn("Cannot extract MimeType for a reference. Reason : [{}]", e.getMessage());
			return null;
		}
	}
	
	private static DigestAlgorithm getDigestAlgorithm(Element dataObjectReference) {
		Element digestMethodElement = DomUtils.getElement(dataObjectReference, ASiCNamespace.DIGEST_METHOD);
		if (digestMethodElement != null) {
			try {
				return DigestAlgorithm.forXML((digestMethodElement).getAttribute(ASiCNamespace.DIGEST_METHOD_ALGORITHM));
			} catch (IllegalArgumentException e) {
				LOG.warn("Unable to extract DigestAlgorithm. Reason : [{}]", e.getMessage());
			}
		}
		return null;
	}
	
	private static byte[] getDigestValue(Element dataObjectReference) {
		Element digestValueElement = DomUtils.getElement(dataObjectReference, ASiCNamespace.DIGEST_VALUE);
		if (digestValueElement != null) {
			try {
				return Utils.fromBase64(digestValueElement.getTextContent());
			} catch (Exception e) {
				LOG.warn("Unable to extract DigestValue. Reason : [{}]", e.getMessage());
			}
		}
		return null;
	}

	private static List<ManifestEntry> parseManifestEntries(Element root) {
		List<ManifestEntry> entries = new ArrayList<ManifestEntry>();
		NodeList dataObjectReferences = DomUtils.getNodeList(root, ASiCNamespace.DATA_OBJECT_REFERENCE);
		if (dataObjectReferences == null || dataObjectReferences.getLength() == 0) {
			LOG.warn("No DataObjectReference found in manifest file");
		} else {
			for (int i = 0; i < dataObjectReferences.getLength(); i++) {
				ManifestEntry entry = new ManifestEntry();
				Element dataObjectReference = (Element) dataObjectReferences.item(i);
				entry.setFileName(dataObjectReference.getAttribute(ASiCNamespace.DATA_OBJECT_REFERENCE_URI));
				entry.setMimeType(getMimeType(dataObjectReference));

				DigestAlgorithm digestAlgorithm = getDigestAlgorithm(dataObjectReference);
				byte[] digestValueBinary = getDigestValue(dataObjectReference);
				if (digestAlgorithm != null && digestValueBinary != null) {
					entry.setDigest(new Digest(digestAlgorithm, digestValueBinary));
				}
				
				String attribute = dataObjectReference.getAttribute(ASiCNamespace.DATA_OBJECT_REFERENCE_ROOTFILE);
				if (attribute != null && ASiCNamespace.DATA_OBJECT_REFERENCE_ROOTFILE_VALUE_TRUE.equals(attribute.toLowerCase())) {
					entry.setRootfile(true);
				}
				
				entries.add(entry);
			}
		}
		return entries;
	}

}
