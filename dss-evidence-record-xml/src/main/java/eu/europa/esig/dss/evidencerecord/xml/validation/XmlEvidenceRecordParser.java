/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.CryptographicInformation;
import eu.europa.esig.dss.evidencerecord.common.validation.CryptographicInformationType;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampIdentifierBuilder;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSAttribute;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class is used to parse an XML Evidence Record
 *
 */
public class XmlEvidenceRecordParser implements EvidenceRecordParser {

    private static final Logger LOG = LoggerFactory.getLogger(XmlEvidenceRecordParser.class);

    /** Element containing the root EvidenceRecord element */
    private final Element evidenceRecordElement;

    /** The name of the file document containing the evidence record */
    private String filename;

    /**
     * Default constructor
     *
     * @param evidenceRecordElement {@link Element}
     */
    public XmlEvidenceRecordParser(final Element evidenceRecordElement) {
        this.evidenceRecordElement = evidenceRecordElement;
    }

    /**
     * Sets a filename of the document containing the evidence record
     *
     * @param filename {@link String}
     * @return this {@link XmlEvidenceRecordParser}
     */
    public XmlEvidenceRecordParser setFilename(String filename) {
        this.filename = filename;
        return this;
    }

    /**
     * Parses the XML Evidence Record object and returns a list of {@code ArchiveTimeStampChainObject}s
     * representing an archive time-stamp sequence
     *
     * @return a list of {@code ArchiveTimeStampChainObject}s
     */
    @Override
    public List<XmlArchiveTimeStampChainObject> parse() {
        final NodeList archiveTimeStampSequenceList = DomUtils.getNodeList(evidenceRecordElement, XMLERSPath.ARCHIVE_TIME_STAMP_CHAIN_PATH);
        if (archiveTimeStampSequenceList != null && archiveTimeStampSequenceList.getLength() > 0) {
            XmlArchiveTimeStampChainObject[] result = new XmlArchiveTimeStampChainObject[archiveTimeStampSequenceList.getLength()];
            for (int i = 0; i < archiveTimeStampSequenceList.getLength(); i++) {
                final Element archiveTimeStampChainElement = (Element) archiveTimeStampSequenceList.item(i);
                XmlArchiveTimeStampChainObject archiveTimeStampChain = getXmlArchiveTimeStampChainObject(archiveTimeStampChainElement, i);
                int order = archiveTimeStampChain.getOrder();
                // TODO : verify order validity
                result[order - 1] = archiveTimeStampChain;
            }
            return Arrays.asList(result);
        }

        return Collections.emptyList();
    }

    private XmlArchiveTimeStampChainObject getXmlArchiveTimeStampChainObject(Element archiveTimeStampChain, int archiveTimeStampChainOrder) {
        XmlArchiveTimeStampChainObject archiveTimeStampChainObject = new XmlArchiveTimeStampChainObject(archiveTimeStampChain);
        archiveTimeStampChainObject.setDigestAlgorithm(getDigestAlgorithm(archiveTimeStampChain));
        archiveTimeStampChainObject.setCanonicalizationMethod(getCanonicalizationMethod(archiveTimeStampChain));
        archiveTimeStampChainObject.setOrder(getOrderAttributeValue(archiveTimeStampChain));
        archiveTimeStampChainObject.setArchiveTimeStamps(getXmlArchiveTimeStamps(archiveTimeStampChain, archiveTimeStampChainOrder));
        return archiveTimeStampChainObject;
    }

    private List<? extends ArchiveTimeStampObject> getXmlArchiveTimeStamps(Element archiveTimeStampChain, int archiveTimeStampChainOrder) {
        final NodeList archiveTimeStampList = DomUtils.getNodeList(archiveTimeStampChain, XMLERSPath.ARCHIVE_TIME_STAMP_PATH);
        if (archiveTimeStampList != null && archiveTimeStampList.getLength() > 0) {
            XmlArchiveTimeStampObject[] result = new XmlArchiveTimeStampObject[archiveTimeStampList.getLength()];
            for (int i = 0; i < archiveTimeStampList.getLength(); i++) {
                final Element archiveTimeStampElement = (Element) archiveTimeStampList.item(i);
                XmlArchiveTimeStampObject archiveTimeStamp = getXmlArchiveTimeStampObject(archiveTimeStampElement, archiveTimeStampChainOrder, i);
                int order = archiveTimeStamp.getOrder();
                result[order - 1] = archiveTimeStamp;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }

    private XmlArchiveTimeStampObject getXmlArchiveTimeStampObject(Element archiveTimeStampElement, int archiveTimeStampChainOrder, int archieTimeStampOrder) {
        XmlArchiveTimeStampObject archiveTimeStampObject = new XmlArchiveTimeStampObject(archiveTimeStampElement);
        archiveTimeStampObject.setHashTree(getHashTree(archiveTimeStampElement));
        archiveTimeStampObject.setTimestampToken(getTimestampToken(archiveTimeStampElement, archiveTimeStampChainOrder, archieTimeStampOrder));
        archiveTimeStampObject.setCryptographicInformationList(getCryptographicInformationList(archiveTimeStampElement));
        archiveTimeStampObject.setOrder(getOrderAttributeValue(archiveTimeStampElement)); // set order attribute value
        return archiveTimeStampObject;
    }

    private TimestampToken getTimestampToken(Element archiveTimeStampElement, int archiveTimeStampChainOrder, int archieTimeStampOrder) {
        Element timeStampTokenElement = DomUtils.getElement(archiveTimeStampElement, XMLERSPath.TIME_STAMP_TOKEN_PATH);
        if (timeStampTokenElement == null) {
            throw new IllegalInputException("TimeStampToken shall be defined!");
        }
        String base64EncodedTimeStamp = timeStampTokenElement.getTextContent();
        if (!Utils.isBase64Encoded(base64EncodedTimeStamp)) {
            throw new IllegalInputException("The content of TimeStampToken shall be represented by a base64-encoded value!");
        }
        try {
            byte[] binaries = Utils.fromBase64(base64EncodedTimeStamp);
            EvidenceRecordTimestampIdentifierBuilder identifierBuilder = new EvidenceRecordTimestampIdentifierBuilder(binaries)
                    .setArchiveTimeStampChainOrder(archiveTimeStampChainOrder)
                    .setArchiveTimeStampOrder(archieTimeStampOrder)
                    .setFilename(filename);
            return new TimestampToken(binaries, TimestampType.EVIDENCE_RECORD_TIMESTAMP, new ArrayList<>(), identifierBuilder);
        } catch (Exception e) {
            LOG.warn("Unable to create a time-stamp token. Reason : {}", e.getMessage(), e);
            return null;
        }
    }

    private List<XmlSequenceObject> getHashTree(Element archiveTimeStampElement) {
        final NodeList hashTree = DomUtils.getNodeList(archiveTimeStampElement, XMLERSPath.HASH_TREE_SEQUENCE_PATH);
        if (hashTree != null && hashTree.getLength() > 0) {
            XmlSequenceObject[] result = new XmlSequenceObject[hashTree.getLength()];
            for (int i = 0; i < hashTree.getLength(); i++) {
                final Element sequenceElement = (Element) hashTree.item(i);
                XmlSequenceObject digestValueGroup = getDigestValueGroup(sequenceElement);
                int order = digestValueGroup.getOrder();
                result[order - 1] = digestValueGroup;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }

    private XmlSequenceObject getDigestValueGroup(Element sequenceElement) {
        XmlSequenceObject digestValueGroup = new XmlSequenceObject(sequenceElement);
        digestValueGroup.setDigestValues(getDigestValues(sequenceElement));
        digestValueGroup.setOrder(getOrderAttributeValue(sequenceElement));
        return digestValueGroup;
    }

    private List<byte[]> getDigestValues(Element sequenceElement) {
        List<byte[]> result = new ArrayList<>();

        final NodeList digestValueList = DomUtils.getNodeList(sequenceElement, XMLERSPath.DIGEST_VALUE_PATH);
        for (int i = 0; i < digestValueList.getLength(); i++) {
            final Element digestValueElement = (Element) digestValueList.item(i);

            String textContent = digestValueElement.getTextContent();
            if (!Utils.isBase64Encoded(textContent)) {
                throw new IllegalInputException("DigestValue is not base64-encoded!");
            }
            result.add(Utils.fromBase64(textContent));
        }

        return result;
    }

    private int getOrderAttributeValue(Element element) {
        String order = element.getAttribute(XMLERSAttribute.ORDER.getAttributeName());
        if (Utils.isStringDigits(order)) {
            return Integer.parseInt(order);
        }
        throw new IllegalInputException("The Order attribute shall be defined!");
    }

    private DigestAlgorithm getDigestAlgorithm(Element archiveTimeStampChainElement) {
        Element digestMethod = DomUtils.getElement(archiveTimeStampChainElement, XMLERSPath.DIGEST_METHOD_PATH);
        if (digestMethod == null) {
            throw new IllegalInputException("The DigestMethod element shall be present!");
        }
        String digestMethodValue = digestMethod.getAttribute(XMLERSAttribute.ALGORITHM.getAttributeName());
        if (Utils.isStringEmpty(digestMethodValue)) {
            throw new IllegalInputException("The Algorithm attribute shall be defined!");
        }
        return DigestAlgorithm.forXML(digestMethodValue);
    }

    private String getCanonicalizationMethod(Element archiveTimeStampChainElement) {
        Element canonicalizationMethod = DomUtils.getElement(archiveTimeStampChainElement, XMLERSPath.CANONICALIZATION_METHOD_PATH);
        if (canonicalizationMethod == null) {
            throw new IllegalInputException("The CanonicalizationMethod element shall be present!");
        }
        String canonicalizationAttribute = canonicalizationMethod.getAttribute(XMLERSAttribute.ALGORITHM.getAttributeName());
        if (Utils.isStringEmpty(canonicalizationAttribute)) {
            throw new IllegalInputException("The Algorithm attribute shall be defined!");
        }
        return canonicalizationAttribute;
    }

    private List<CryptographicInformation> getCryptographicInformationList(Element archiveTimeStampElement) {
        NodeList cryptographicInformationNodeList = DomUtils.getNodeList(archiveTimeStampElement, XMLERSPath.CRYPTOGRAPHIC_INFORMATION_PATH);
        if (cryptographicInformationNodeList == null || cryptographicInformationNodeList.getLength() == 0) {
            return Collections.emptyList();
        }

        final List<CryptographicInformation> cryptographicInformationList = new ArrayList<>();
        for (int i = 0; i < cryptographicInformationNodeList.getLength(); i++) {
            Element cryptographicInformationElement = (Element) cryptographicInformationNodeList.item(i);
            String type = cryptographicInformationElement.getAttribute(XMLERSAttribute.TYPE.getAttributeName());
            if (Utils.isStringEmpty(type)) {
                LOG.warn("Type attribute shall be defined within CryptographicInformation element! Element is skipped.");
                continue;
            }
            CryptographicInformationType cryptographicInformationType = CryptographicInformationType.fromLabel(type);

            String textContent = cryptographicInformationElement.getTextContent();
            if (!Utils.isBase64Encoded(textContent)) {
                LOG.warn("Value within CryptographicInformation element shall be base64-encoded! Element is skipped.");
                continue;
            }

            cryptographicInformationList.add(
                    new CryptographicInformation(Utils.fromBase64(textContent), cryptographicInformationType));
        }

        return cryptographicInformationList;
    }

}
