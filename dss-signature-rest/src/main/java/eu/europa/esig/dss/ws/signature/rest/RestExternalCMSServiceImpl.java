package eu.europa.esig.dss.ws.signature.rest;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteExternalCMSService;
import eu.europa.esig.dss.ws.signature.dto.DataToSignExternalCmsDTO;
import eu.europa.esig.dss.ws.signature.dto.SignMessageDigestExternalCmsDTO;
import eu.europa.esig.dss.ws.signature.rest.client.RestExternalCMSService;

/**
 * REST implementation of the remote CMS signature generation suitable for PAdES signature creation
 *
 */
public class RestExternalCMSServiceImpl implements RestExternalCMSService {

    private static final long serialVersionUID = 6958836951128294905L;

    /** The service to use */
    private RemoteExternalCMSService service;

    /**
     * Default construction instantiating object with null RestExternalCMSServiceImpl
     */
    public RestExternalCMSServiceImpl() {
        // empty
    }

    /**
     * Sets the remote service for external CMS creation suitable for PAdES signing
     *
     * @param service {@link RemoteExternalCMSService}
     */
    public void setService(RemoteExternalCMSService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(DataToSignExternalCmsDTO dataToSign) {
        return service.getDataToSign(dataToSign.getMessageDigest(), dataToSign.getParameters());
    }

    @Override
    public RemoteDocument signMessageDigest(SignMessageDigestExternalCmsDTO signMessageDigest) {
        return service.signMessageDigest(signMessageDigest.getMessageDigest(), signMessageDigest.getParameters(),
                signMessageDigest.getSignatureValue());
    }

}
