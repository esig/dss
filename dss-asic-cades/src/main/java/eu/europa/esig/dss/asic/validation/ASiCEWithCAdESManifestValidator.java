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
package eu.europa.esig.dss.asic.validation;

import java.io.InputStream;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.ASiCNamespace;
import eu.europa.esig.dss.utils.Utils;

public class ASiCEWithCAdESManifestValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithCAdESManifestValidator.class);

	static {
		DomUtils.registerNamespace("asic", ASiCNamespace.NS);
	}

	private final DSSDocument signature;
	private final List<DSSDocument> manifestDocuments;
	private final List<DSSDocument> signedDocuments;

	public ASiCEWithCAdESManifestValidator(DSSDocument signature, List<DSSDocument> manifestDocuments, List<DSSDocument> signedDocuments) {
		this.signature = signature;
		this.manifestDocuments = manifestDocuments;
		this.signedDocuments = signedDocuments;
	}

	public DSSDocument getLinkedManifest() {
		String expectedSignatureURI = signature.getName();
		for (DSSDocument manifestDocument : manifestDocuments) {
			try (InputStream is = manifestDocument.openStream()) {
				Document manifestDom = DomUtils.buildDOM(is);
				Element root = DomUtils.getElement(manifestDom, ASiCNamespace.ASIC_MANIFEST);
				String signatureURI = DomUtils.getValue(root, ASiCNamespace.SIG_REFERENCE_URI);
				if (Utils.areStringsEqual(expectedSignatureURI, signatureURI) && checkManifestDigests(root)) {
					return manifestDocument;
				}
			} catch (Exception e) {
				LOG.warn("Unable to analyze manifest file '{}' : {}", manifestDocument.getName(), e.getMessage());
			}
		}
		return null;
	}

	private boolean checkManifestDigests(Element root) {
		NodeList dataObjectReferences = DomUtils.getNodeList(root, ASiCNamespace.DATA_OBJECT_REFERENCE);
		if (dataObjectReferences == null || dataObjectReferences.getLength() == 0) {
			LOG.warn("No DataObjectReference found in manifest file");
			return false;
		} else {
			for (int i = 0; i < dataObjectReferences.getLength(); i++) {
				Element dataObjectReference = (Element) dataObjectReferences.item(i);

				String filename = dataObjectReference.getAttribute("URI");

				DSSDocument signedFile = getSignedFileByName(filename);
				if (signedFile == null) {
					LOG.warn("Signed data with name '{}' not found", filename);
					return false;
				}

				DigestAlgorithm digestAlgo = getDigestAlgorithm(dataObjectReference);
				if (digestAlgo == null) {
					LOG.warn("Digest algo is not defined for signed data with name '{}'", filename);
					return false;
				}

				String expectedDigestB64 = getDigestValue(dataObjectReference);
				String computedDigestB64 = signedFile.getDigest(digestAlgo);
				if (!Utils.areStringsEqual(expectedDigestB64, computedDigestB64)) {
					LOG.warn("Digest value doesn't match for signed data with name '{}'", filename);
					LOG.warn("Expected : '{}'", expectedDigestB64);
					LOG.warn("Computed : '{}'", computedDigestB64);
					return false;
				}

			}
		}

		return true;
	}

	private DSSDocument getSignedFileByName(String filename) {
		for (DSSDocument signedDocument : signedDocuments) {
			if (Utils.areStringsEqual(filename, signedDocument.getName())) {
				return signedDocument;
			}
		}
		return null;
	}

	private DigestAlgorithm getDigestAlgorithm(Element element) {
		final String xmlName = DomUtils.getElement(element, "ds:DigestMethod").getAttribute("Algorithm");
		return DigestAlgorithm.forXML(xmlName, null);
	}

	private String getDigestValue(Element element) {
		Element digestValueElement = DomUtils.getElement(element, "ds:DigestValue");
		if (digestValueElement != null) {
			return digestValueElement.getTextContent();
		}
		return Utils.EMPTY_STRING;
	}

}
