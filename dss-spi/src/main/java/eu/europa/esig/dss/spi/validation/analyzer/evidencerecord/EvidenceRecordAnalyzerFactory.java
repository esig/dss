package eu.europa.esig.dss.spi.validation.analyzer.evidencerecord;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzerFactory;

import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This class is used to load a corresponding implementation of {@code EvidenceRecordAnalyzer}
 * for processing of an evidence record document
 *
 */
public interface EvidenceRecordAnalyzerFactory extends DocumentAnalyzerFactory {

    /**
     * This method tests if the current implementation of {@link EvidenceRecordAnalyzer}
     * supports the given document
     *
     * @param document
     *                 the document to be tested
     * @return true, if the {@link EvidenceRecordAnalyzer} supports the given document
     */
    boolean isSupported(DSSDocument document);

    /**
     * This method instantiates a {@link EvidenceRecordAnalyzer} with the given document
     *
     * @param document
     *                 the document to be used for the {@link EvidenceRecordAnalyzer}
     *                 creation
     * @return an instance of {@link EvidenceRecordAnalyzer} with the document
     */
    EvidenceRecordAnalyzer create(DSSDocument document);

    /**
     * Verifies if the {@code document} is supported by one of the implementations,
     * across {@code EvidenceRecordValidatorFactory} instances found by ServiceLoader.
     *
     * @param document {@link DSSDocument} to verify
     * @return TRUE if the evidence record is supported by one of the found implementations, FALSE otherwise
     */
    static boolean isSupportedDocument(DSSDocument document) {
        Objects.requireNonNull(document, "DSSDocument is null");
        ServiceLoader<EvidenceRecordAnalyzerFactory> serviceLoaders = ServiceLoader.load(EvidenceRecordAnalyzerFactory.class);
        for (EvidenceRecordAnalyzerFactory factory : serviceLoaders) {
            if (factory.isSupported(document)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Creates an {@code EvidenceRecordValidator} by loading a corresponding implementation,
     * across {@code EvidenceRecordValidatorFactory} instances found by ServiceLoader.
     *
     * @param document {@link DSSDocument} to load validator for
     * @return {@link EvidenceRecordAnalyzer} if corresponding implementation found
     * @throws UnsupportedOperationException is the document format is not supported or implementation is not found
     */
    static EvidenceRecordAnalyzer fromDocument(DSSDocument document) throws UnsupportedOperationException {
        Objects.requireNonNull(document, "DSSDocument is null");
        ServiceLoader<EvidenceRecordAnalyzerFactory> serviceLoaders = ServiceLoader.load(EvidenceRecordAnalyzerFactory.class);
        for (EvidenceRecordAnalyzerFactory factory : serviceLoaders) {
            if (factory.isSupported(document)) {
                return factory.create(document);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

}
