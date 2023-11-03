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
package eu.europa.esig.dss.asic.common.validation;

import eu.europa.esig.asic.manifest.definition.ASiCManifestAttribute;
import eu.europa.esig.asic.manifest.definition.ASiCManifestNamespace;
import eu.europa.esig.asic.manifest.definition.ASiCManifestPath;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.ASiCManifestTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xmldsig.definition.XMLDSigNamespace;
import eu.europa.esig.xmldsig.definition.XMLDSigPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses ASiC Manifest file and produces a {@code ManifestFile}
 *
 */
public class ASiCManifestParser {

    private static final Logger LOG = LoggerFactory.getLogger(ASiCManifestParser.class);

    static {
        DomUtils.registerNamespace(XMLDSigNamespace.NS);
        DomUtils.registerNamespace(ASiCManifestNamespace.NS);
    }

    /**
     * Default constructor
     */
    private ASiCManifestParser() {
        // empty
    }

    /**
     * Parses and converts {@code DSSDocument} to {@code ManifestFile}
     *
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
        manifest.setManifestType(getManifestType(manifestDocument.getName(), root));
        return manifest;
    }

    /**
     * Returns the relative manifests for the given signature name
     *
     * @param manifestDocuments list of found manifests {@link DSSDocument} in the container (candidates)
     * @param signatureName {@link String} name of the signature to get related manifest for
     * @return {@link DSSDocument} the related manifests
     */
    public static DSSDocument getLinkedManifest(List<DSSDocument> manifestDocuments, String signatureName) {
        for (DSSDocument manifest : manifestDocuments) {
            Element manifestRoot = getManifestRootElement(manifest);
            if (manifestRoot != null) {
                String linkedSignatureName = DSSUtils.decodeURI(getLinkedSignatureName(manifestRoot));
                if (signatureName.equals(linkedSignatureName)) {
                    return manifest;
                }
            }
        }
        return null;
    }

    private static Element getManifestRootElement(DSSDocument manifestDocument) {
        if (!DomUtils.isDOM(manifestDocument)) {
            LOG.warn("Unable to analyze manifest file '{}' : Not a valid XML file!", manifestDocument.getName());
            return null;
        }
        try {
            Document manifestDom = DomUtils.buildDOM(manifestDocument);
            return DomUtils.getElement(manifestDom, ASiCManifestPath.ASIC_MANIFEST_PATH);
        } catch (Exception e) {
            LOG.warn("Unable to analyze manifest file '{}' : {}", manifestDocument.getName(), e.getMessage());
            return null;
        }
    }

    private static String getLinkedSignatureName(Element root) {
        return DomUtils.getValue(root, ASiCManifestPath.SIG_REFERENCE_URI_PATH);
    }

    private static MimeType getMimeType(Element element) {
        try {
            String mimeTypeString = element.getAttribute(ASiCManifestAttribute.MIME_TYPE.getAttributeName());
            if (Utils.isStringNotBlank(mimeTypeString)) {
                return MimeType.fromMimeTypeString(mimeTypeString);
            }
        } catch (DSSException e) {
            LOG.warn("Cannot extract MimeType for a reference. Reason : [{}]", e.getMessage());
        }
        return null;
    }

    private static DigestAlgorithm getDigestAlgorithm(Element dataObjectReference) {
        String value = null;
        try {
            value = DomUtils.getValue(dataObjectReference, XMLDSigPath.DIGEST_METHOD_ALGORITHM_PATH);
            return DigestAlgorithm.forXML(value);
        } catch (IllegalArgumentException e) {
            LOG.warn("Unable to extract DigestAlgorithm (value = {}). Reason : [{}]", value, e.getMessage());
        }
        return null;
    }

    private static byte[] getDigestValue(Element dataObjectReference) {
        try {
            Element digestValueElement = DomUtils.getElement(dataObjectReference, XMLDSigPath.DIGEST_VALUE_PATH);
            if (digestValueElement != null) {
                String digest = digestValueElement.getTextContent();
                if (Utils.isBase64Encoded(digest)) {
                    return Utils.fromBase64(digestValueElement.getTextContent());
                } else {
                    LOG.warn("The manifest entry digest value is not base64-encoded!");
                }
            }
        } catch (Exception e) {
            LOG.warn("Unable to extract DigestValue. Reason : [{}]", e.getMessage());
        }
        return null;
    }

    private static ASiCManifestTypeEnum getManifestType(String manifestFilename, Element root) {
        if (ASiCUtils.isArchiveManifest(manifestFilename)) {
            return ASiCManifestTypeEnum.ARCHIVE_MANIFEST;
        } else if (ASiCUtils.isEvidenceRecordManifest(manifestFilename)) {
            return ASiCManifestTypeEnum.EVIDENCE_RECORD;
        } else if (ASiCUtils.isManifest(manifestFilename)) {
            Element sigReference = DomUtils.getElement(root, ASiCManifestPath.SIG_REFERENCE_PATH);
            if (sigReference != null) {
                MimeType mimeType = getMimeType(sigReference);
                return MimeTypeEnum.TST == mimeType ? ASiCManifestTypeEnum.TIMESTAMP : ASiCManifestTypeEnum.SIGNATURE;
            }
        }
        return null;
    }

    private static List<ManifestEntry> parseManifestEntries(Element root) {
        List<ManifestEntry> entries = new ArrayList<>();
        NodeList dataObjectReferences = DomUtils.getNodeList(root, ASiCManifestPath.DATA_OBJECT_REFERENCE_PATH);
        if (dataObjectReferences == null || dataObjectReferences.getLength() == 0) {
            LOG.warn("No DataObjectReference found in manifest file");
        } else {
            for (int i = 0; i < dataObjectReferences.getLength(); i++) {
                ManifestEntry entry = new ManifestEntry();
                Element dataObjectReference = (Element) dataObjectReferences.item(i);
                entry.setFileName(DSSUtils.decodeURI(dataObjectReference.getAttribute(ASiCManifestAttribute.URI.getAttributeName())));
                entry.setMimeType(getMimeType(dataObjectReference));

                DigestAlgorithm digestAlgorithm = getDigestAlgorithm(dataObjectReference);
                byte[] digestValueBinary = getDigestValue(dataObjectReference);
                if (digestAlgorithm != null && digestValueBinary != null) {
                    entry.setDigest(new Digest(digestAlgorithm, digestValueBinary));
                }

                String attribute = dataObjectReference.getAttribute(ASiCManifestAttribute.ROOTFILE.getAttributeName());
                if (Utils.areStringsEqualIgnoreCase("true", attribute)) {
                    entry.setRootfile(true);
                }

                entries.add(entry);
            }
        }
        return entries;
    }

}
