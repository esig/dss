package eu.europa.esig.dss.ws.signature.soap.client;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalMessageDigestDTO;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalSignDocumentDTO;

import java.io.Serializable;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

/**
 * This SOAP interface provides a possibility of PAdES signature creation using an external CMS signature provider
 *
 */
@WebService(targetNamespace = "http://signature.dss.esig.europa.eu/")
public interface SoapPAdESWithExternalCMSService extends Serializable {

    /**
     * Creates a signature revision for the provided PDF document according
     * to the defined parameters and returns the message-digest computed on the extracted ByteRange content.
     *
     * @param pdfMessageDigest
     *            {@link PDFExternalMessageDigestDTO} containing a PDF document to be singed and signature parameters
     * @return {@link DigestDTO} representing message-digest computed on the prepared PDF signature byte range
     */
    @WebResult(name = "response")
    DigestDTO getMessageDigest(@WebParam(name = "pdfMessageDigest") PDFExternalMessageDigestDTO pdfMessageDigest);

    /**
     * Signs the {@code toSignDocument} by incorporating the provided {@code cmsSignature}
     * within computed PDF signature revision.
     *
     * @param pdfSignDocument
     *            {@link PDFExternalSignDocumentDTO} containing a PDF document, set of driven signature creation
     *            parameters and a CMS signature document
     * @return {@link RemoteDocument} representing a PDF signed document embedding the provided CMS signature
     */
    @WebResult(name = "response")
    RemoteDocument signDocument(@WebParam(name = "pdfSignDocument") PDFExternalSignDocumentDTO pdfSignDocument);

}
