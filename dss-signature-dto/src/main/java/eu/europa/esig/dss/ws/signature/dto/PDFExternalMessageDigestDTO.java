package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

/**
 * Represents a DataTransferObject containing the required parameters for computation of message-digest
 * of the prepared PDF signature revision (to be used for PAdES signature creation with an external CMS provider).
 * <p>
 * It's only possible to transfer an object by POST and REST.
 *
 */
public class PDFExternalMessageDigestDTO extends DataToSignOneDocumentDTO {

    private static final long serialVersionUID = 4116757487911778822L;

    /**
     * Empty constructor
     */
    public PDFExternalMessageDigestDTO() {
        super();
    }

    /**
     * Default constructor
     *
     * @param toSignDocument {@link RemoteDocument} to be signed
     * @param parameters {@link RemoteSignatureParameters}
     */
    public PDFExternalMessageDigestDTO(RemoteDocument toSignDocument, RemoteSignatureParameters parameters) {
        super(toSignDocument, parameters);
    }

    @Override
    public String toString() {
        return "PDFMessageDigestDTO [toSignDocument=" + getToSignDocument() + ", parameters=" + getParameters() + "]";
    }

}
