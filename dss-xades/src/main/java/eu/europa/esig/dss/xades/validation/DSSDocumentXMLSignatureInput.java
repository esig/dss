package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.io.InputStream;

/**
 * This class represents an implementation of an {@code XMLSignatureInput} created on a base of {@code DSSDocument}
 *
 */
public class DSSDocumentXMLSignatureInput extends CloseableXMLSignatureInput {

    /** The detached document to be provided */
    private final DSSDocument document;

    /**
     * Default constructor for an {@code XMLSignatureInput} from a detached document
     *
     * @param document {@link DSSDocument}
     */
    public DSSDocumentXMLSignatureInput(final DSSDocument document) {
        super(toInputStream(document));
        this.document = document;
    }

    private static InputStream toInputStream(DSSDocument document) {
        return document.openStream();
    }

    /**
     * Constructor for an {@code XMLSignatureInput} from a base64-encoded document digest
     *
     * @param document {@link DSSDocument}
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for a digest computation
     */
    protected DSSDocumentXMLSignatureInput(final DSSDocument document, final DigestAlgorithm digestAlgorithm) {
        super(getBase64Digest(document, digestAlgorithm));
        this.document = document;
    }

    private static String getBase64Digest(DSSDocument document, DigestAlgorithm digestAlgorithm) {
        byte[] digestValue = document.getDigestValue(digestAlgorithm);
        return Utils.toBase64(digestValue);
    }

    @Override
    public String getMIMEType() {
        if (document.getMimeType() != null) {
            return document.getMimeType().getMimeTypeString();
        }
        return null;
    }

    /**
     * Returns a document name
     *
     * @return {@link String}
     */
    public String getDocumentName() {
        return document.getName();
    }

}
