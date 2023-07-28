package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.evidencerecord.xml.XmlEvidenceRecordUtils;
import eu.europa.esig.dss.evidencerecord.xml.validation.timestamp.XMLEvidenceRecordTimestampSource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.xmlers.XMLEvidenceRecordUtils;
import org.w3c.dom.Element;

import javax.xml.transform.dom.DOMSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * XML Evidence Record implementations (RFC 6283)
 *
 */
public class XmlEvidenceRecord extends EvidenceRecord {

    /** The current signature element */
    private final Element evidenceRecordElement;

    /** Cached instance of timestamp source */
    private XMLEvidenceRecordTimestampSource timestampSource;

    /**
     * Default constructor to instantiate an XML Evidence Record from a root element
     *
     * @param evidenceRecordElement {@link Element} representing the 'ers:EvidenceRecord' element
     */
    public XmlEvidenceRecord(final Element evidenceRecordElement) {
        this.evidenceRecordElement = evidenceRecordElement;
    }

    /**
     * Gets the EvidenceRecord XML Element
     *
     * @return {@link Element}
     */
    public Element getEvidenceRecordElement() {
        return evidenceRecordElement;
    }

    @Override
    protected List<XmlArchiveTimeStampChainObject> buildArchiveTimeStampSequence() {
        return new XmlEvidenceRecordParser(evidenceRecordElement).parse();
    }

    @Override
    public EvidenceRecordTimestampSource<?> getTimestampSource() {
        if (timestampSource == null) {
            timestampSource = new XMLEvidenceRecordTimestampSource(this);
        }
        return timestampSource;
    }

    /**
     * Performs validation of the detached content and returns back the validity results
     *
     * @return a list of {@link ReferenceValidation} objects corresponding to each archive data object validation
     */
    public List<ReferenceValidation> getReferenceValidation() {
        if (referenceValidations == null) {
            referenceValidations = new ArrayList<>();

            List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = getArchiveTimeStampSequence();
            for (int i = 0; i < archiveTimeStampSequence.size(); i++) {
                XmlArchiveTimeStampChainObject xmlArchiveTimeStampChain = (XmlArchiveTimeStampChainObject) archiveTimeStampSequence.get(i);
                DigestAlgorithm digestAlgorithm = xmlArchiveTimeStampChain.getDigestAlgorithm();
                String canonicalizationMethod = xmlArchiveTimeStampChain.getCanonicalizationMethod();

                List<? extends ArchiveTimeStampObject> archiveTimeStamps = xmlArchiveTimeStampChain.getArchiveTimeStamps();
                if (Utils.isCollectionNotEmpty(archiveTimeStamps)) {
                    ArchiveTimeStampObject archiveTimeStamp = archiveTimeStamps.get(0);
                    List<? extends DigestValueGroup> hashTree = archiveTimeStamp.getHashTree();
                    if (Utils.isCollectionNotEmpty(hashTree)) {
                        DigestValueGroup digestValueGroup = hashTree.get(0);

                        List<ReferenceValidation> invalidReferences = new ArrayList<>();
                        for (byte[] hashValue : digestValueGroup.getDigestValues()) {
                            ReferenceValidation referenceValidation = new ReferenceValidation();
                            referenceValidation.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

                            Digest digest = new Digest(digestAlgorithm, hashValue);
                            referenceValidation.setDigest(new Digest(digestAlgorithm, hashValue));

                            DSSDocument matchingDocument = getMatchingDocument(digest, canonicalizationMethod);
                            if (matchingDocument != null) {
                                referenceValidation.setFound(true);
                                referenceValidation.setIntact(true);
                                referenceValidation.setName(matchingDocument.getName());

                                referenceValidations.add(referenceValidation);

                            } else {
                                referenceValidation.setFound(false);
                                referenceValidation.setIntact(false);

                                invalidReferences.add(referenceValidation);
                            }
                        }

                        // TODO : review
                        if (i == 0 || invalidReferences.size() > 1) {
                            // The first sequence of following ArchiveTimeStampChain shall contain a canonicalization result of previous ArchiveTimeStampSequence
                            referenceValidations.addAll(invalidReferences);
                        }
                    }
                }
            }
        }
        return referenceValidations;
    }

    /**
     * This method returns a document with matching {@code Digest} from a provided list of {@code detachedContents}
     *
     * @param digest {@link Digest} to check
     * @param canonicalizationMethod {@link String} to be applied on XML archive data objects
     * @return {@link DSSDocument} if matching document found, NULL otherwise
     */
    private DSSDocument getMatchingDocument(Digest digest, String canonicalizationMethod) {
        for (DSSDocument document : getDetachedContents()) {
            byte[] documentDigest;
            if (!(document instanceof DigestDocument) && DomUtils.isDOM(document)) {
                byte[] canonicalizedDocument = XmlEvidenceRecordUtils.canonicalize(canonicalizationMethod, DSSUtils.toByteArray(document));
                documentDigest = DSSUtils.digest(digest.getAlgorithm(), canonicalizedDocument);
            } else {
                String base64Digest = document.getDigest(digest.getAlgorithm());
                documentDigest = Utils.fromBase64(base64Digest);
            }
            if (Arrays.equals(digest.getValue(), documentDigest)) {
                return document;
            }
        }
        return null;
    }

    @Override
    public List<String> validateStructure() {
        return XMLEvidenceRecordUtils.getInstance().validateAgainstXSD(new DOMSource(evidenceRecordElement));
    }

}
