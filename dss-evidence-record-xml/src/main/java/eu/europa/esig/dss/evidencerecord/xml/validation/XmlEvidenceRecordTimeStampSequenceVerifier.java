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
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.xmlers.definition.XMLERSAttribute;
import eu.europa.esig.xmlers.definition.XMLERSElement;
import eu.europa.esig.xmlers.definition.XMLERSPath;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 * Verifies ArchiveTimeStampSequence for an XML Evidence Record
 *
 */
public class XmlEvidenceRecordTimeStampSequenceVerifier extends EvidenceRecordTimeStampSequenceVerifier {

    /**
     * Default constructor to instantiate an XML evidence record verifier
     *
     * @param evidenceRecord {@link XmlEvidenceRecord} XML evidence record to be validated
     */
    public XmlEvidenceRecordTimeStampSequenceVerifier(XmlEvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    protected DataObjectDigestBuilder getDataObjectDigestBuilder(DSSDocument document, ArchiveTimeStampChainObject archiveTimeStampChain) {
        DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();
        String canonicalizationMethod = getCanonicalizationMethod(archiveTimeStampChain);
        return new XMLEvidenceRecordDataObjectDigestBuilder(document, digestAlgorithm)
                .setCanonicalizationMethod(canonicalizationMethod);
    }

    /**
     * Extracts a canonicalization method defined within XML {@code ArchiveTimeStampChainObject}
     *
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} to get canonicalization method definition from
     * @return {@link String} canonicalization method
     */
    protected String getCanonicalizationMethod(ArchiveTimeStampChainObject archiveTimeStampChain) {
        XmlArchiveTimeStampChainObject xmlArchiveTimeStampChainObject = (XmlArchiveTimeStampChainObject) archiveTimeStampChain;
        return xmlArchiveTimeStampChainObject.getCanonicalizationMethod();
    }

    @Override
    protected List<? extends DigestValueGroup> getHashTree(
            List<? extends DigestValueGroup> originalHashTree, List<DSSDocument> detachedContents,
            ArchiveTimeStampChainObject archiveTimeStampChain, DSSMessageDigest lastTimeStampHash, DSSMessageDigest lastTimeStampSequenceHash) {
        final List<? extends DigestValueGroup> hashTree = super.getHashTree(
                originalHashTree, detachedContents, archiveTimeStampChain, lastTimeStampHash, lastTimeStampSequenceHash);

        // HashTree renewal time-stamp shall cover one or more data objects
        if (lastTimeStampSequenceHash != null && !lastTimeStampSequenceHash.isEmpty()) {
            DigestValueGroup firstDigestValueGroup = hashTree.get(0);
            if (Utils.collectionSize(firstDigestValueGroup.getDigestValues()) == 1) {
                List<byte[]> newDigestValuesGroup = new ArrayList<>(firstDigestValueGroup.getDigestValues());
                newDigestValuesGroup.add(DSSUtils.EMPTY_BYTE_ARRAY);
                firstDigestValueGroup.setDigestValues(newDigestValuesGroup);
            }
        }

        return hashTree;
    }

    @Override
    protected DSSMessageDigest computeTimeStampHash(DigestAlgorithm digestAlgorithm,
            ArchiveTimeStampObject archiveTimeStamp, ArchiveTimeStampChainObject archiveTimeStampChain) {
        String canonicalizationMethod = getCanonicalizationMethod(archiveTimeStampChain);
        XmlArchiveTimeStampObject xmlArchiveTimeStampObject = (XmlArchiveTimeStampObject) archiveTimeStamp;
        Element archiveTimeStampElement = xmlArchiveTimeStampObject.getElement();
        Element timeStampElement = DomUtils.getElement(archiveTimeStampElement, XMLERSPath.TIME_STAMP_PATH);
        byte[] canonicalizedSubtree = XMLCanonicalizer.createInstance(canonicalizationMethod).canonicalize(timeStampElement);
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, canonicalizedSubtree);
        return new DSSMessageDigest(digestAlgorithm, digestValue);
    }

    @Override
    protected DSSMessageDigest computePrecedingTimeStampSequenceHash(
            ArchiveTimeStampChainObject archiveTimeStampChain, List<DSSDocument> detachedContents) {
        DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();
        XmlArchiveTimeStampChainObject xmlArchiveTimeStampChainObject = (XmlArchiveTimeStampChainObject) archiveTimeStampChain;

        Document documentCopy = createDocumentCopy();
        Element archiveTimeStampSequence = DomUtils.getElement(documentCopy.getDocumentElement(), XMLERSPath.ARCHIVE_TIME_STAMP_SEQUENCE_PATH);
        NodeList childNodes = archiveTimeStampSequence.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node node = childNodes.item(i);
            if (Node.ELEMENT_NODE == node.getNodeType() && XMLERSElement.ARCHIVE_TIME_STAMP_CHAIN.isSameTagName(node.getLocalName())) {
                Element archiceTimeStampChainElement = (Element) node;
                String order = archiceTimeStampChainElement.getAttribute(XMLERSAttribute.ORDER.getAttributeName());
                if (Utils.isStringNotEmpty(order) && Utils.isStringDigits(order)) {
                    int intOrder = Integer.parseInt(order);
                    if (intOrder >= xmlArchiveTimeStampChainObject.getOrder()) {
                        archiveTimeStampSequence.removeChild(node);
                    }
                }
            }
        }
        byte[] canonicalizedSubtree = XMLCanonicalizer.createInstance(xmlArchiveTimeStampChainObject.getCanonicalizationMethod())
                .canonicalize(archiveTimeStampSequence);
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, canonicalizedSubtree);
        return new DSSMessageDigest(digestAlgorithm, digestValue);
    }

    private Document createDocumentCopy() {
        XmlEvidenceRecord xmlEvidenceRecord = (XmlEvidenceRecord) evidenceRecord;
        Element evidenceRecordElement = xmlEvidenceRecord.getEvidenceRecordElement();

        Node originalRoot = evidenceRecordElement.getOwnerDocument().getDocumentElement();

        Document documentCopy = DomUtils.buildDOM();
        Node copiedRoot = documentCopy.importNode(originalRoot, true);
        documentCopy.appendChild(copiedRoot);
        return documentCopy;
    }

}
