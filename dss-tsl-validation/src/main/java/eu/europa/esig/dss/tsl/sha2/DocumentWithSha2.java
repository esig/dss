package eu.europa.esig.dss.tsl.sha2;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSDocument;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to represent a downloaded {@code eu.europa.esig.dss.model.DSSDocument}
 * with its corresponding ".sha2" file
 *
 */
public class DocumentWithSha2 extends CommonDocument {

    private static final long serialVersionUID = -6370847348735932510L;

    /** The original downloaded document */
    private final DSSDocument document;

    /** The corresponding sha2 document, containing digests of the {@code document} */
    private final DSSDocument sha2Document;

    /** List of errors occurred during .sha2 document processing */
    private List<String> errors;

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} original downloaded document
     * @param sha2Document {@link DSSDocument} corresponding sha2 document, containing digests of the {@code document}
     */
    protected DocumentWithSha2(final DSSDocument document, final DSSDocument sha2Document) {
        this.document = document;
        this.sha2Document = sha2Document;
    }

    /**
     * Gets the original document
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getDocument() {
        return document;
    }

    /**
     * Gets the downloaded sha2 document corresponding to the {@code document}
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getSha2Document() {
        return sha2Document;
    }

    /**
     * This method adds an error message occurred during the .sha2 file validation
     *
     * @param errorMessage {@link String} error
     */
    protected void addErrorMessage(String errorMessage) {
        if (errors == null) {
            errors = new ArrayList<>();
        }
        errors.add(errorMessage);
    }

    /**
     * Returns a list of errors occurred during processing of .sha2 document.
     * Returns NULL if validation succeeded.
     *
     * @return a list of {@link String} errors, if any
     */
    public List<String> getErrors() {
        return errors;
    }

    @Override
    public InputStream openStream() {
        Objects.requireNonNull(document, "Document is null! Unable to open InputStream.");
        return document.openStream();
    }

}
