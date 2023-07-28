package eu.europa.esig.dss.evidencerecord.xml.validation.timestamp;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampMessageDigestBuilder;
import eu.europa.esig.dss.evidencerecord.xml.XmlEvidenceRecordUtils;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSAttribute;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSElement;
import eu.europa.esig.dss.evidencerecord.xml.definition.XMLERSPaths;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlEvidenceRecord;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * This class is used to build a message-digest for verification of an Evidence Record Time-Stamp
 *
 */
public class XMLEvidenceRecordTimestampMessageDigestBuilder extends EvidenceRecordTimestampMessageDigestBuilder {

    /**
     * Constructor to instantiate XMLEvidenceRecordTimestampMessageDigestBuilder in order to compute
     * a message-imprint for {@code XmlEvidenceRecordTimestampAttribute} validation
     *
     * @param evidenceRecord {@link XmlEvidenceRecord}
     * @param archiveTimeStampObject {@link ArchiveTimeStampObject}
     */
    public XMLEvidenceRecordTimestampMessageDigestBuilder(final XmlEvidenceRecord evidenceRecord,
                                                          final ArchiveTimeStampObject archiveTimeStampObject) {
        super(evidenceRecord, archiveTimeStampObject);
    }

    @Override
    protected DSSMessageDigest computeTimeStampHash(DigestAlgorithm digestAlgorithm, ArchiveTimeStampObject archiveTimeStamp) {
        XmlArchiveTimeStampObject xmlArchiveTimeStampObject = (XmlArchiveTimeStampObject) archiveTimeStamp;
        XmlArchiveTimeStampChainObject xmlArchiveTimeStampChainObject = (XmlArchiveTimeStampChainObject) xmlArchiveTimeStampObject.getParent();
        Element archiveTimeStampElement = xmlArchiveTimeStampObject.getElement();
        Element timeStampElement = DomUtils.getElement(archiveTimeStampElement, XMLERSPaths.TIME_STAMP_PATH);
        byte[] canonicalizedSubtree = XmlEvidenceRecordUtils.canonicalizeSubtree(xmlArchiveTimeStampChainObject.getCanonicalizationMethod(), timeStampElement);
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, canonicalizedSubtree);
        return new DSSMessageDigest(digestAlgorithm, digestValue);
    }

    @Override
    protected DSSMessageDigest computeTimeStampSequenceHash(DigestAlgorithm digestAlgorithm, ArchiveTimeStampChainObject targetArchiveTimeStampChain) {
        XmlArchiveTimeStampChainObject targetXmlArchiveTimeStampChainObject = (XmlArchiveTimeStampChainObject) targetArchiveTimeStampChain;

        Document documentCopy = createDocumentCopy();
        Element archiveTimeStampSequence = DomUtils.getElement(documentCopy.getDocumentElement(), XMLERSPaths.ARCHIVE_TIME_STAMP_SEQUENCE_PATH);
        NodeList childNodes = archiveTimeStampSequence.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node node = childNodes.item(i);
            if (Node.ELEMENT_NODE == node.getNodeType() && XMLERSElement.ARCHIVE_TIME_STAMP_CHAIN.isSameTagName(node.getLocalName())) {
                Element archiceTimeStampChainElement = (Element) node;
                String order = archiceTimeStampChainElement.getAttribute(XMLERSAttribute.ORDER.getAttributeName());
                if (Utils.isStringNotEmpty(order) && Utils.isStringDigits(order)) {
                    int intOrder = Integer.parseInt(order);
                    if (intOrder >= targetXmlArchiveTimeStampChainObject.getOrder()) {
                        archiveTimeStampSequence.removeChild(node);
                    }
                }
            }
        }
        byte[] canonicalizedSubtree = XmlEvidenceRecordUtils.canonicalizeSubtree(
                targetXmlArchiveTimeStampChainObject.getCanonicalizationMethod(), archiveTimeStampSequence);
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
