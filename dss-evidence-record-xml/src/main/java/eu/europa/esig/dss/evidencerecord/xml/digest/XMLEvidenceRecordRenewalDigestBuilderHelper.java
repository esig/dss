package eu.europa.esig.dss.evidencerecord.xml.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.digest.AbstractEvidenceRecordRenewalDigestBuilderHelper;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlEvidenceRecord;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
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

/**
 * This class contains supporting method for XMLERS evidence record renewal
 *
 */
public class XMLEvidenceRecordRenewalDigestBuilderHelper extends AbstractEvidenceRecordRenewalDigestBuilderHelper {

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link XmlEvidenceRecord}
     */
    public XMLEvidenceRecordRenewalDigestBuilderHelper(final XmlEvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    public DSSMessageDigest buildTimeStampRenewalDigest(ArchiveTimeStampObject archiveTimeStamp) {
        XmlArchiveTimeStampChainObject archiveTimeStampChain = (XmlArchiveTimeStampChainObject) getArchiveTimeStampChainObject(archiveTimeStamp);
        return buildTimeStampRenewalDigest(archiveTimeStamp, archiveTimeStampChain.getDigestAlgorithm(), archiveTimeStampChain.getCanonicalizationMethod());
    }

    /**
     * This method builds digest for a time-stamp renewal with the specified {@code digestAlgorithm}
     *
     * @param archiveTimeStamp {@link ArchiveTimeStampObject} to build digest on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on digest computation
     * @return {@link Digest}
     */
    public DSSMessageDigest buildTimeStampRenewalDigest(ArchiveTimeStampObject archiveTimeStamp, DigestAlgorithm digestAlgorithm, String canonicalizationMethod) {
        XmlArchiveTimeStampObject xmlArchiveTimeStampObject = (XmlArchiveTimeStampObject) archiveTimeStamp;
        Element archiveTimeStampElement = xmlArchiveTimeStampObject.getElement();
        Element timeStampElement = DomUtils.getElement(archiveTimeStampElement, XMLERSPath.TIME_STAMP_PATH);
        byte[] canonicalizedSubtree = XMLCanonicalizer.createInstance(canonicalizationMethod).canonicalize(timeStampElement);
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, canonicalizedSubtree);
        return new DSSMessageDigest(digestAlgorithm, digestValue);
    }

    @Override
    public DSSMessageDigest buildArchiveTimeStampSequenceDigest(ArchiveTimeStampChainObject archiveTimeStampChain) {
        XmlArchiveTimeStampChainObject nextArchiveTimeStampChain = (XmlArchiveTimeStampChainObject) getNextArchiveTimeStampChain(archiveTimeStampChain);
        return buildArchiveTimeStampSequenceDigest(nextArchiveTimeStampChain.getDigestAlgorithm(),
                nextArchiveTimeStampChain.getCanonicalizationMethod(), nextArchiveTimeStampChain.getOrder());
    }

    /**
     * This method builds digest for a time-stamp chain renewal with the specified {@code digestAlgorithm} and {@code canonicalizationMethod}
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on digest computation
     * @param canonicalizationMethod {@link String}
     * @param archiveTimeStampChainOrder of the time-stamp chain to compute digest for its first time-stamp
     * @return {@link Digest}
     */
    public DSSMessageDigest buildArchiveTimeStampSequenceDigest(DigestAlgorithm digestAlgorithm, String canonicalizationMethod, int archiveTimeStampChainOrder) {
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
                    if (archiveTimeStampChainOrder != -1 && intOrder >= archiveTimeStampChainOrder) {
                        archiveTimeStampSequence.removeChild(node);
                    }
                }
            }
        }

        byte[] canonicalizedSubtree = XMLCanonicalizer.createInstance(canonicalizationMethod)
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