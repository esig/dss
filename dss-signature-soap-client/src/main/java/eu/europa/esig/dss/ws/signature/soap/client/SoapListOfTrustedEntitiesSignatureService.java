package eu.europa.esig.dss.ws.signature.soap.client;


import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignListOfTrustedEntitiesDTO;
import eu.europa.esig.dss.ws.signature.dto.SignListOfTrustedEntitiesDTO;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

import java.io.Serializable;

/**
 * SOAP interface provides services for List of Trusted Entities signing
 *
 */
@WebService(targetNamespace = "http://signature.dss.esig.europa.eu/")
public interface SoapListOfTrustedEntitiesSignatureService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed based on the given List of Trusted Entities and parameters.
     *
     * @param dataToSign {@link DataToSignListOfTrustedEntitiesDTO} a DTO with the needed information
     *                   (list of trusted entities and parameters) to compute the data to be signed
     * @return {@link ToBeSignedDTO} the data to be signed
     */
    @WebResult(name = "response")
    ToBeSignedDTO getDataToSign(@WebParam(name = "dataToSignDTO") DataToSignListOfTrustedEntitiesDTO dataToSign);

    /**
     * Signs the List of Trusted Entities with the provided signatureValue.
     * <p>
     * NOTE: the same set of parameters shall be used for this method call,
     *       as it was for {@code getDataToSign(dataToSign)} method
     *
     * @param signListOfTrustedEntities {@link SignListOfTrustedEntitiesDTO} a DTO with the needed information
     *                                  (list of trusted entities, parameter and signature value) to generate
     *                                  the signed List of Trusted Entities with an enveloped signature
     * @return {@link RemoteDocument} the signed document
     */
    @WebResult(name = "response")
    RemoteDocument signDocument(@WebParam(name = "signDocumentDTO") SignListOfTrustedEntitiesDTO signListOfTrustedEntities);

}
