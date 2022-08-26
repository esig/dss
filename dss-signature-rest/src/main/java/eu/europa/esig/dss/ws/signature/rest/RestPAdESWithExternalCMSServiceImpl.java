package eu.europa.esig.dss.ws.signature.rest;

import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.common.RemotePAdESWithExternalCMSService;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalMessageDigestDTO;
import eu.europa.esig.dss.ws.signature.dto.PDFExternalSignDocumentDTO;
import eu.europa.esig.dss.ws.signature.rest.client.RestPAdESWithExternalCMSService;

/**
 * REST implementation of the remote PAdES signature with external CMS service
 *
 */
public class RestPAdESWithExternalCMSServiceImpl implements RestPAdESWithExternalCMSService {

    private static final long serialVersionUID = 7258729288847441656L;

    /** The service to use */
    private RemotePAdESWithExternalCMSService service;

    /**
     * Default construction instantiating object with null RestPAdESWithExternalCMSServiceImpl
     */
    public RestPAdESWithExternalCMSServiceImpl() {
        // empty
    }

    /**
     * Sets the remote PAdES signature with external CMS service
     *
     * @param service {@link RemotePAdESWithExternalCMSService}
     */
    public void setService(RemotePAdESWithExternalCMSService service) {
        this.service = service;
    }

    @Override
    public DigestDTO getMessageDigest(PDFExternalMessageDigestDTO pdfMessageDigest) {
        return service.getMessageDigest(pdfMessageDigest.getToSignDocument(), pdfMessageDigest.getParameters());
    }

    @Override
    public RemoteDocument signDocument(PDFExternalSignDocumentDTO pdfSignDocument) {
        return service.signDocument(pdfSignDocument.getToSignDocument(), pdfSignDocument.getParameters(),
                pdfSignDocument.getCmsDocument());
    }

}
