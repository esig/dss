package eu.europa.esig.dss.ws.signature.soap;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteTrustedListSignatureService;
import eu.europa.esig.dss.ws.signature.dto.DataToSignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.dto.SignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.soap.client.SoapTrustedListSignatureService;

/**
 * SOAP implementation for XML Trusted List signing service
 *
 */
public class SoapTrustedListSignatureServiceImpl implements SoapTrustedListSignatureService {

    private static final long serialVersionUID = -2982455071210880177L;

    /** The service to use */
    private RemoteTrustedListSignatureService service;

    /**
     * Sets the remote XML Trusted List signing service
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
