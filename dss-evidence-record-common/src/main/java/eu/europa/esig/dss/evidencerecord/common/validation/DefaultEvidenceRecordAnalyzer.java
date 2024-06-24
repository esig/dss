package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class contains common method for processing of evidence record documents
 *
 */
public abstract class DefaultEvidenceRecordAnalyzer extends DefaultDocumentAnalyzer implements EvidenceRecordAnalyzer {

    /** Cached instance of evidence record */
    private EvidenceRecord evidenceRecord;

    /**
     * Empty constructor
     */
    protected DefaultEvidenceRecordAnalyzer() {
        // empty
    }

    /**
     * Instantiates the class with a document to be validated
     *
     * @param document {@link DSSDocument} to be validated
     */
    protected DefaultEvidenceRecordAnalyzer(DSSDocument document) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");
        this.document = document;
    }

    /**
     * This method guesses the document format and returns an appropriate
     * evidence record reader.
     *
     * @param dssDocument
     *            The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of {@link DefaultEvidenceRecordAnalyzer} in terms of the document type
     */
    public static EvidenceRecordAnalyzer fromDocument(final DSSDocument dssDocument) {
        return EvidenceRecordAnalyzerFactory.fromDocument(dssDocument);
    }

    @Override
    public EvidenceRecord getEvidenceRecord() {
        if (evidenceRecord == null) {
            evidenceRecord = buildEvidenceRecord();

            List<SignatureScope> evidenceRecordScopes = getEvidenceRecordScopes(evidenceRecord);
            evidenceRecord.setEvidenceRecordScopes(evidenceRecordScopes);
            evidenceRecord.setTimestampedReferences(getTimestampedReferences(evidenceRecordScopes));
        }
        return evidenceRecord;
    }

    /**
     * Builds an evidence record object
     *
     * @return {@link EvidenceRecord}
     */
    protected abstract EvidenceRecord buildEvidenceRecord();

    @Override
    public List<EvidenceRecord> getDetachedEvidenceRecords() {
        return Collections.singletonList(getEvidenceRecord());
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        throw new UnsupportedOperationException("getOriginalDocuments(AdvancedSignature) is " +
                "not supported for EvidenceRecordValidator!");
    }

    @Override
    public abstract EvidenceRecordTypeEnum getEvidenceRecordType();

}
