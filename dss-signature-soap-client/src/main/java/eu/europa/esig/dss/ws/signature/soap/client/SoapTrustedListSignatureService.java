package eu.europa.esig.dss.ws.signature.soap.client;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.dto.SignTrustedListDTO;

import java.io.Serializable;

/**
 * SOAP interface provides services for XML Trusted List signing
 *
 */
@WebService(targetNamespace = "http://signature.dss.esig.europa.eu/")
public interface SoapTrustedListSignatureService extends Serializable {

    /**
     * This method computes the digest to be signed for XML Trusted List enveloped signature creation
     *
     * @param dataToSign {@link DataToSignOneDocumentDTO} a DTO which contains the XML Trusted List to be signed
     *                                                   and parameters
     * @return {@link ToBeSignedDTO} the data to be signed
     */
    @WebResult(name = "response")
    ToBeSignedDTO getDataToSign(@WebParam(name = "dataToSignDTO") DataToSignTrustedListDTO dataToSign);

    /**
     * This method created a signed XML Trusted List with an enveloped signature
     *
     * @param signTrustedList {@link SignTrustedListDTO} a DTO which contains the XMl Trusted List to be signed,
     *                                                  the parameters and the signature value
     * @return {@link RemoteDocument} the signed document
     */
    @WebResult(name = "response")
    RemoteDocument signDocument(@WebParam(name = "signDocumentDTO") SignTrustedListDTO signTrustedList);

}
