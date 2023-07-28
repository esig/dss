package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.OrderableComparator;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSAttribute;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSPaths;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to parse an XML Evidence Record
 */
public class XmlEvidenceRecordParser {

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
    public List<XmlArchiveTimeStampChainObject> parse() {
        final List<XmlArchiveTimeStampChainObject> archiveTimeStampSequence = new ArrayList<>();

        final NodeList archiveTimeStampSequenceList = DomUtils.getNodeList(evidenceRecordElement, XMLERSPaths.ARCHIVE_TIME_STAMP_CHAIN_PATH);
        if (archiveTimeStampSequenceList != null && archiveTimeStampSequenceList.getLength() > 0) {
            for (int i = 0; i < archiveTimeStampSequenceList.getLength(); i++) {
                final Element archiveTimeStampChain = (Element) archiveTimeStampSequenceList.item(i);
                archiveTimeStampSequence.add(getXmlArchiveTimeStampChainObject(archiveTimeStampChain));
            }
        }

        archiveTimeStampSequence.sort(new OrderableComparator());
        return archiveTimeStampSequence;
    }

    private XmlArchiveTimeStampChainObject getXmlArchiveTimeStampChainObject(Element archiveTimeStampChain) {
        XmlArchiveTimeStampChainObject archiveTimeStampChainObject = new XmlArchiveTimeStampChainObject(archiveTimeStampChain);
        archiveTimeStampChainObject.setDigestAlgorithm(getDigestAlgorithm(archiveTimeStampChain));
        archiveTimeStampChainObject.setCanonicalizationMethod(getCanonicalizationMethod(archiveTimeStampChain));
        archiveTimeStampChainObject.setOrder(getOrderAttributeValue(archiveTimeStampChain));
        archiveTimeStampChainObject.setArchiveTimeStamps(getXmlArchiveTimeStamps(archiveTimeStampChain, archiveTimeStampChainObject));
        return archiveTimeStampChainObject;
    }

    private List<? extends ArchiveTimeStampObject> getXmlArchiveTimeStamps(Element archiveTimeStampChain, XmlArchiveTimeStampChainObject parent) {
        final List<XmlArchiveTimeStampObject> result = new ArrayList<>();

        final NodeList archiveTimeStampList = DomUtils.getNodeList(archiveTimeStampChain, XMLERSPaths.ARCHIVE_TIME_STAMP_PATH);
        if (archiveTimeStampList != null && archiveTimeStampList.getLength() > 0) {
            for (int i = 0; i < archiveTimeStampList.getLength(); i++) {
                final Element archiveTimeStampElement = (Element) archiveTimeStampList.item(i);
                result.add(getXmlArchiveTimeStampObject(archiveTimeStampElement, parent));
            }
        }

        result.sort(new OrderableComparator());
        return result;
    }

    private XmlArchiveTimeStampObject getXmlArchiveTimeStampObject(Element archiveTimeStampElement, XmlArchiveTimeStampChainObject parent) {
        XmlArchiveTimeStampObject archiveTimeStampObject = new XmlArchiveTimeStampObject(archiveTimeStampElement);
        archiveTimeStampObject.setOrder(getOrderAttributeValue(archiveTimeStampElement));
        archiveTimeStampObject.setHashTree(getHashTree(archiveTimeStampElement));
        archiveTimeStampObject.setTimestampToken(getTimestampToken(archiveTimeStampElement));
        archiveTimeStampObject.setParent(parent);
        return archiveTimeStampObject;
    }

    private byte[] getTimestampToken(Element archiveTimeStampElement) {
        Element timeStampTokenElement = DomUtils.getElement(archiveTimeStampElement, XMLERSPaths.TIME_STAMP_TOKEN_PATH);
        if (timeStampTokenElement == null) {
            throw new IllegalInputException("TimeStampToken shall be defined!");
        }
        String base64EncodedTimeStamp = timeStampTokenElement.getTextContent();
        if (!Utils.isBase64Encoded(base64EncodedTimeStamp)) {
            throw new IllegalInputException("The content of TimeStampToken shall be represented by a base64-encoded value!");
        }
        return Utils.fromBase64(base64EncodedTimeStamp);
    }

    private List<XmlSequenceObject> getHashTree(Element archiveTimeStampElement) {
        List<XmlSequenceObject> result = new ArrayList<>();

        final NodeList hashTree = DomUtils.getNodeList(archiveTimeStampElement, XMLERSPaths.HASH_TREE_SEQUENCE_PATH);
        for (int i = 0; i < hashTree.getLength(); i++) {
            final Element sequenceElement = (Element) hashTree.item(i);
            result.add(getDigestValueGroup(sequenceElement));
        }

        result.sort(new OrderableComparator());
        return result;
    }

    private XmlSequenceObject getDigestValueGroup(Element sequenceElement) {
        XmlSequenceObject digestValueGroup = new XmlSequenceObject(sequenceElement);
        digestValueGroup.setOrder(getOrderAttributeValue(sequenceElement));
        digestValueGroup.setDigestValues(getDigestValues(sequenceElement));
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
