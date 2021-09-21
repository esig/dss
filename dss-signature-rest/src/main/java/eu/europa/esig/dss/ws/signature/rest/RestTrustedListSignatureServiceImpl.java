package eu.europa.esig.dss.ws.signature.rest;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteTrustedListSignatureService;
import eu.europa.esig.dss.ws.signature.dto.DataToSignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.dto.SignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.rest.client.RestTrustedListSignatureService;

/**
 * REST implementation of the remote trusted list signing service
 *
 */
public class RestTrustedListSignatureServiceImpl implements RestTrustedListSignatureService {

    private static final long serialVersionUID = 2929769970186252017L;

    /** The service to use */
    private RemoteTrustedListSignatureService service;

    /**
     * Sets the remote service for XML Trusted List signing
     *
     * @param service {@link RemoteTrustedListSignatureService}
     */
    public void setService(RemoteTrustedListSignatureService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(DataToSignTrustedListDTO dataToSign) {
        return service.getDataToSign(dataToSign.getTrustedList(), dataToSign.getParameters());
    }

    @Override
    public RemoteDocument signDocument(SignTrustedListDTO signTrustedList) {
        return service.signDocument(signTrustedList.getTrustedList(), signTrustedList.getParameters(),
                signTrustedList.getSignatureValue());
    }

}
