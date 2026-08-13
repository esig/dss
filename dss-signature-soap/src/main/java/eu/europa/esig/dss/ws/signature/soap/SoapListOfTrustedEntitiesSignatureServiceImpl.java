package eu.europa.esig.dss.ws.signature.soap;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteListOfTrustedEntitiesSignatureService;
import eu.europa.esig.dss.ws.signature.dto.DataToSignListOfTrustedEntitiesDTO;
import eu.europa.esig.dss.ws.signature.dto.SignListOfTrustedEntitiesDTO;
import eu.europa.esig.dss.ws.signature.soap.client.SoapListOfTrustedEntitiesSignatureService;

/**
 * SOAP implementation of the remote list of trusted entities signing service
 *
 */
public class SoapListOfTrustedEntitiesSignatureServiceImpl implements SoapListOfTrustedEntitiesSignatureService {

    private static final long serialVersionUID = 2929769970186252017L;

    /** The service to use */
    private RemoteListOfTrustedEntitiesSignatureService service;

    /**
     * Default construction instantiating object with null RemoteListOfTrustedEntitiesSignatureService
     */
    public SoapListOfTrustedEntitiesSignatureServiceImpl() {
        // empty
    }

    /**
     * Sets the remote service for List of Trusted Entities signing
     *
     * @param service {@link RemoteListOfTrustedEntitiesSignatureService}
     */
    public void setService(RemoteListOfTrustedEntitiesSignatureService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(DataToSignListOfTrustedEntitiesDTO dataToSign) {
        return service.getDataToSign(dataToSign.getListOfTrustedEntities(), dataToSign.getParameters());
    }

    @Override
    public RemoteDocument signDocument(SignListOfTrustedEntitiesDTO signListOfTrustedEntities) {
        return service.signDocument(signListOfTrustedEntities.getListOfTrustedEntities(), signListOfTrustedEntities.getParameters(),
                signListOfTrustedEntities.getSignatureValue());
    }

}
