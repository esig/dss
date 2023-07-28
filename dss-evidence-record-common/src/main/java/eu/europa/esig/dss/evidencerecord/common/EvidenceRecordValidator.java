package eu.europa.esig.dss.evidencerecord.common;

import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecord;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.reports.Reports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Abstract class containing the basic logic for an Evidence Record validation,
 * as well as containing a loader for an Evidence Record validation of the given format.
 *
 */
public abstract class EvidenceRecordValidator {

    private static final Logger LOG = LoggerFactory.getLogger(EvidenceRecordValidator.class);

    /** Document to be validated */
    protected DSSDocument document;

    /**
     * A time to validate the document against
     */
    private Date validationTime;

    /**
     * Contains a list of documents time-stamped within a reduced HashTree
     */
    protected List<DSSDocument> detachedContents = new ArrayList<>();

    /**
     * Empty constructor
     */
    protected EvidenceRecordValidator() {
        // empty
    }

    /**
     * Instantiates the class with a document to be validated
     *
     * @param document {@link DSSDocument} to be validated
     */
    protected EvidenceRecordValidator(DSSDocument document) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");
        this.document = document;
    }

    /**
     * This method guesses the document format and returns an appropriate
     * evidence record validator.
     *
     * @param dssDocument
     *            The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of {@link EvidenceRecordValidator} in terms of the document type
     */
    public static EvidenceRecordValidator fromDocument(final DSSDocument dssDocument) {
        Objects.requireNonNull(dssDocument, "DSSDocument is null");
        ServiceLoader<EvidenceRecordValidatorFactory> serviceLoaders = ServiceLoader.load(EvidenceRecordValidatorFactory.class);
        for (EvidenceRecordValidatorFactory factory : serviceLoaders) {
            if (factory.isSupported(dssDocument)) {
                return factory.create(dssDocument);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

    /**
     * Checks if the document is supported by the current validator
     *
     * @param dssDocument {@link DSSDocument} to check
     * @return TRUE if the document is supported, FALSE otherwise
     */
    public abstract boolean isSupported(DSSDocument dssDocument);

    /**
     * Allows to define a custom validation time
     *
     * @param validationTime {@link Date}
     */
    public void setValidationTime(Date validationTime) {
        this.validationTime = validationTime;
    }

    /**
     * Returns validation time In case if the validation time is not provided,
     * initialize the current time value from the system
     *
     * @return {@link Date} validation time
     */
    protected Date getValidationTime() {
        if (validationTime == null) {
            validationTime = new Date();
        }
        return validationTime;
    }

    /**
     * Sets a list of time-stamped documents present in the initial sequence of the reduced HashTree
     *
     * @param detachedContents a list of {@link DSSDocument}s
     */
    public void setDetachedContents(final List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    /**
     * Validates the document containing Evidence Record
     *
     * @return {@link Reports}
     */
    public abstract Reports validateDocument();

    /**
     * Returns an evidence record extracted from the document
     *
     * @return {@link EvidenceRecord}
     */
    public abstract EvidenceRecord getEvidenceRecord();

}
