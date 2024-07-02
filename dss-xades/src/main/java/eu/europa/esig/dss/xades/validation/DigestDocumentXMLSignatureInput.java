package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DigestDocument;

/**
 * This class is use for a {@code XMLSignatureInput} definition from a {@code DigestDocument}
 *
 */
public class DigestDocumentXMLSignatureInput extends DSSDocumentXMLSignatureInput {

    /**
     * Constructor for an {@code XMLSignatureInput} from a {@code DigestDocument}
     *
     * @param document {@link DigestDocument}
     * @param digestAlgorithm {@link DigestAlgorithm} used for the corresponding reference digest computation
     */
    public DigestDocumentXMLSignatureInput(final DigestDocument document, DigestAlgorithm digestAlgorithm) {
        super(document, digestAlgorithm);
    }

}
