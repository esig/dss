package eu.europa.esig.dss.ws.signature.rest.client;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalMessageDigestDTO;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalSignDocumentDTO;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.Serializable;

/**
 * This REST interface provides a possibility of PAdES signature creation using an external CMS signature provider
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestPAdESWithExternalCMSService extends Serializable {

    /**
     * Creates a signature revision for the provided PDF document according
     * to the defined parameters and returns the message-digest computed on the extracted ByteRange content.
     *
     * @param pdfMessageDigest
     *            {@link PDFExternalMessageDigestDTO} containing a PDF document to be singed and signature parameters
     * @return {@link DigestDTO} representing message-digest computed on the prepared PDF signature byte range
     */
    @POST
    @Path("getMessageDigest")
    DigestDTO getMessageDigest(PDFExternalMessageDigestDTO pdfMessageDigest);

    /**
     * Signs the {@code toSignDocument} by incorporating the provided {@code cmsSignature}
     * within computed PDF signature revision.
     *
     * @param pdfSignDocument
     *            {@link PDFExternalSignDocumentDTO} containing a PDF document, set of driven signature creation
     *            parameters and a CMS signature document
     * @return {@link RemoteDocument} representing a PDF signed document embedding the provided CMS signature
     */
    @POST
    @Path("signDocument")
    RemoteDocument signDocument(PDFExternalSignDocumentDTO pdfSignDocument);

}
