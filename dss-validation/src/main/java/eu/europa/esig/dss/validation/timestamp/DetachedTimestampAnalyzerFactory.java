package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzerFactory;

/**
 * This class analyzes conformance of a document to a timestamp format and creates
 * a corresponding {@code DetachedTimestampProcessor} for its validation
 *
 */
public class DetachedTimestampAnalyzerFactory implements DocumentAnalyzerFactory {

    /**
     * Default constructor
     */
    public DetachedTimestampAnalyzerFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        DetachedTimestampAnalyzer reader = new DetachedTimestampAnalyzer();
        return reader.isSupported(document);
    }

    @Override
    public DocumentAnalyzer create(DSSDocument document) {
        return new DetachedTimestampAnalyzer(document);
    }

}
