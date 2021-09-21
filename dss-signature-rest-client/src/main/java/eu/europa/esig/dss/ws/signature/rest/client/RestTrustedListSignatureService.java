package eu.europa.esig.dss.ws.signature.rest.client;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.dto.SignTrustedListDTO;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.Serializable;

/**
 * This REST interface provides operations for the XML Trusted List signing.
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestTrustedListSignatureService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed based on the given XML Trusted List and parameters.
     *
     * @param dataToSign {@link DataToSignTrustedListDTO} a DTO with the needed information
     *                                                   (trusted list and parameters) to compute the data to be signed
     * @return {@link ToBeSignedDTO} the data to be signed
     */
    @POST
    @Path("getDataToSign")
    ToBeSignedDTO getDataToSign(DataToSignTrustedListDTO dataToSign);

    /**
     * Signs the XML Trusted List with the provided signatureValue.
     *
     * NOTE: the same set of parameters shall be used for this method call,
     *       as it was for {@code getDataToSign(dataToSign)} method
     *
     * @param signTrustedList {@link SignTrustedListDTO} a DTO with the needed information
     *                                               (trusted list, parameter and signature value) to generate
     *                                               the signed XML Trusted List with an enveloped signature
     * @return {@link RemoteDocument} the signed document
     */
    @POST
    @Path("signDocument")
    RemoteDocument signDocument(SignTrustedListDTO signTrustedList);

}
