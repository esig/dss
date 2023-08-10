package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.xmlers.definition.XMLERSAttribute;
import eu.europa.esig.xmlers.definition.XMLERSPaths;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
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

    /**
     * Default constructor
     *
     * @param evidenceRecordElement {@link Element}
     */
    public XmlEvidenceRecordParser(final Element evidenceRecordElement) {
        this.evidenceRecordElement = evidenceRecordElement;
    }

    /**
     * Parses the XML Evidence Record object and returns a list of {@code ArchiveTimeStampChainObject}s
     * representing an archive time-stamp sequence
     *
     * @return a list of {@code ArchiveTimeStampChainObject}s
     */
    @Override
    public List<XmlArchiveTimeStampChainObject> parse() {
        final NodeList archiveTimeStampSequenceList = DomUtils.getNodeList(evidenceRecordElement, XMLERSPaths.ARCHIVE_TIME_STAMP_CHAIN_PATH);
        if (archiveTimeStampSequenceList != null && archiveTimeStampSequenceList.getLength() > 0) {
            XmlArchiveTimeStampChainObject[] result = new XmlArchiveTimeStampChainObject[archiveTimeStampSequenceList.getLength()];
            for (int i = 0; i < archiveTimeStampSequenceList.getLength(); i++) {
                final Element archiveTimeStampChainElement = (Element) archiveTimeStampSequenceList.item(i);
                XmlArchiveTimeStampChainObject archiveTimeStampChain = getXmlArchiveTimeStampChainObject(archiveTimeStampChainElement);
                int order = archiveTimeStampChain.getOrder();
                // TODO : verify order validity
                result[order - 1] = archiveTimeStampChain;
            }
            return Arrays.asList(result);
        }

        return Collections.emptyList();
    }

    private XmlArchiveTimeStampChainObject getXmlArchiveTimeStampChainObject(Element archiveTimeStampChain) {
        XmlArchiveTimeStampChainObject archiveTimeStampChainObject = new XmlArchiveTimeStampChainObject(archiveTimeStampChain);
        archiveTimeStampChainObject.setDigestAlgorithm(getDigestAlgorithm(archiveTimeStampChain));
        archiveTimeStampChainObject.setCanonicalizationMethod(getCanonicalizationMethod(archiveTimeStampChain));
        archiveTimeStampChainObject.setOrder(getOrderAttributeValue(archiveTimeStampChain));
        archiveTimeStampChainObject.setArchiveTimeStamps(getXmlArchiveTimeStamps(archiveTimeStampChain));
        return archiveTimeStampChainObject;
    }

    private List<? extends ArchiveTimeStampObject> getXmlArchiveTimeStamps(Element archiveTimeStampChain) {
        final NodeList archiveTimeStampList = DomUtils.getNodeList(archiveTimeStampChain, XMLERSPaths.ARCHIVE_TIME_STAMP_PATH);
        if (archiveTimeStampList != null && archiveTimeStampList.getLength() > 0) {
            XmlArchiveTimeStampObject[] result = new XmlArchiveTimeStampObject[archiveTimeStampList.getLength()];
            for (int i = 0; i < archiveTimeStampList.getLength(); i++) {
                final Element archiveTimeStampElement = (Element) archiveTimeStampList.item(i);
                XmlArchiveTimeStampObject archiveTimeStamp = getXmlArchiveTimeStampObject(archiveTimeStampElement);
                int order = archiveTimeStamp.getOrder();
                result[order - 1] = archiveTimeStamp;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }

    private XmlArchiveTimeStampObject getXmlArchiveTimeStampObject(Element archiveTimeStampElement) {
        XmlArchiveTimeStampObject archiveTimeStampObject = new XmlArchiveTimeStampObject(archiveTimeStampElement);
        archiveTimeStampObject.setHashTree(getHashTree(archiveTimeStampElement));
        archiveTimeStampObject.setTimestampToken(getTimestampToken(archiveTimeStampElement));
        archiveTimeStampObject.setOrder(getOrderAttributeValue(archiveTimeStampElement));
        return archiveTimeStampObject;
    }

    private TimestampToken getTimestampToken(Element archiveTimeStampElement) {
        Element timeStampTokenElement = DomUtils.getElement(archiveTimeStampElement, XMLERSPaths.TIME_STAMP_TOKEN_PATH);
        if (timeStampTokenElement == null) {
            throw new IllegalInputException("TimeStampToken shall be defined!");
        }
        String base64EncodedTimeStamp = timeStampTokenElement.getTextContent();
        if (!Utils.isBase64Encoded(base64EncodedTimeStamp)) {
            throw new IllegalInputException("The content of TimeStampToken shall be represented by a base64-encoded value!");
        }
        try {
            return new TimestampToken(Utils.fromBase64(base64EncodedTimeStamp), TimestampType.EVIDENCE_RECORD_TIMESTAMP);
        } catch (Exception e) {
            LOG.warn("Unable to create a time-stamp token. Reason : {}", e.getMessage(), e);
            return null;
        }
    }

    private List<XmlSequenceObject> getHashTree(Element archiveTimeStampElement) {
        final NodeList hashTree = DomUtils.getNodeList(archiveTimeStampElement, XMLERSPaths.HASH_TREE_SEQUENCE_PATH);
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

        final NodeList digestValueList = DomUtils.getNodeList(sequenceElement, XMLERSPaths.DIGEST_VALUE_PATH);
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
        Element digestMethod = DomUtils.getElement(archiveTimeStampChainElement, XMLERSPaths.DIGEST_METHOD_PATH);
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
        Element canonicalizationMethod = DomUtils.getElement(archiveTimeStampChainElement, XMLERSPaths.CANONICALIZATION_METHOD_PATH);
        if (canonicalizationMethod == null) {
            throw new IllegalInputException("The CanonicalizationMethod element shall be present!");
        }
        String canonicalizationAttribute = canonicalizationMethod.getAttribute(XMLERSAttribute.ALGORITHM.getAttributeName());
        if (Utils.isStringEmpty(canonicalizationAttribute)) {
            throw new IllegalInputException("The Algorithm attribute shall be defined!");
        }
        return canonicalizationAttribute;
    }

}
