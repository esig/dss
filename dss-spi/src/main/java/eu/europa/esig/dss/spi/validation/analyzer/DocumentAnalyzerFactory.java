package eu.europa.esig.dss.spi.validation.analyzer;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This interface is used to analyze the format of the given {@code DSSDocument} and
 * create a corresponding implementation of {@code DocumentAnalyzer}
 *
 */
public interface DocumentAnalyzerFactory {

    /**
     * This method tests if the current implementation of {@link DocumentAnalyzer}
     * supports the given document
     *
     * @param document
     *                 the document to be tested
     * @return true, if the {@link DocumentAnalyzer} supports the given document
     */
    boolean isSupported(DSSDocument document);

    /**
     * This method instantiates a {@link DocumentAnalyzer} with the given document
     *
     * @param document
     *                 the document to be used for the {@link DocumentAnalyzer}
     *                 creation
     * @return an instance of {@link DocumentAnalyzer} with the document
     */
    DocumentAnalyzer create(DSSDocument document);

}
