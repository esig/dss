package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Provides a user-friendly interface for dealing with JAXB {@code eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord} object
 *
 */
public class EvidenceRecordWrapper {

    /** Wrapped XML Evidence Record object */
    private final XmlEvidenceRecord evidenceRecord;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link XmlEvidenceRecord}
     */
    public EvidenceRecordWrapper(final XmlEvidenceRecord evidenceRecord) {
        Objects.requireNonNull(evidenceRecord, "XmlEvidenceRecord cannot be null!");
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Gets unique identifier
     *
     * @return {@link String}
     */
    public String getId() {
        return evidenceRecord.getId();
    }

    /**
     * Returns name of the evidence record's document, when applicable
     *
     * @return {@link String}
     */
    public String getFilename() {
        return evidenceRecord.getDocumentName();
    }

    /**
     * Gets a list of digest matchers representing the associated archival data objects validation status
     *
     * @return a list of {@link XmlDigestMatcher}
     */
    public List<XmlDigestMatcher> getDigestMatchers() {
        return evidenceRecord.getDigestMatchers();
    }

    /**
     * Returns initial time-stamp of the evidence record
     *
     * @return {@link TimestampWrapper}
     */
    public TimestampWrapper getFirstTimestamp() {
        List<TimestampWrapper> timestampList = getTimestampList();
        if (timestampList != null && timestampList.size() > 0) {
            return timestampList.get(0);
        }
        return null;
    }

    /**
     * Gets a list of time-stamp tokens associated with the evidence record
     *
     * @return a list of {@link TimestampWrapper}s
     */
    public List<TimestampWrapper> getTimestampList() {
        List<TimestampWrapper> tsps = new ArrayList<>();
        List<XmlFoundTimestamp> timestamps = evidenceRecord.getEvidenceRecordTimestamps();
        for (XmlFoundTimestamp xmlFoundTimestamp : timestamps) {
            tsps.add(new TimestampWrapper(xmlFoundTimestamp.getTimestamp()));
        }
        return tsps;
    }

    /**
     * Returns a list of time-stamp identifiers associated with the Evidence Record
     *
     * @return a list of {@link String}s
     */
    public List<String> getTimestampIdsList() {
        List<String> result = new ArrayList<>();
        List<TimestampWrapper> timestamps = getTimestampList();
        if (timestamps != null) {
            for (TimestampWrapper tsp : timestamps) {
                result.add(tsp.getId());
            }
        }
        return result;
    }

    /**
     * Gets the evidence record format type
     *
     * @return {@link EvidenceRecordTypeEnum}
     */
    public EvidenceRecordTypeEnum getEvidenceRecordType() {
        return evidenceRecord.getType();
    }

    /**
     * Gets if a structural validation of the evidence record is valid
     *
     * @return TRUE if the structure of the evidence record is valid, FALSE otherwise
     */
    public boolean isStructuralValidationValid() {
        return evidenceRecord.getStructuralValidation() != null && evidenceRecord.getStructuralValidation().isValid();
    }

    /**
     * Returns structural validation error messages, when applicable
     *
     * @return a list of {@link String} error messages
     */
    public List<String> getStructuralValidationMessages() {
        XmlStructuralValidation structuralValidation = evidenceRecord.getStructuralValidation();
        if (structuralValidation != null) {
            return structuralValidation.getMessages();
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of objects covered by the evidence record
     *
     * @return a list of {@link XmlTimestampedObject}s
     */
    public List<XmlTimestampedObject> getCoveredObjects() {
        return evidenceRecord.getTimestampedObjects();
    }

    /**
     * Returns Evidence record's Signature Scopes
     *
     * @return a list of {@link XmlSignatureScope}s
     */
    public List<XmlSignatureScope> getEvidenceRecordScopes() {
        return evidenceRecord.getEvidenceRecordScopes();
    }

}
