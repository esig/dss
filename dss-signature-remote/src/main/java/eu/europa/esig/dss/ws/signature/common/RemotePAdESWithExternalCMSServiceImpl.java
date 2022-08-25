package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * WebService for PAdES signature creation using an external CMS signature provider
 *
 */
public class RemotePAdESWithExternalCMSServiceImpl extends AbstractRemoteSignatureServiceImpl
        implements RemotePAdESWithExternalCMSService {

    private static final long serialVersionUID = -5681970320686504972L;

    private static final Logger LOG = LoggerFactory.getLogger(RemotePAdESWithExternalCMSServiceImpl.class);

    /** PAdES signature service */
    private PAdESWithExternalCMSService service;

    /**
     * Default constructor instantiating object with null RemotePAdESWithExternalCMSServiceImpl
     */
    public RemotePAdESWithExternalCMSServiceImpl() {
        // empty
    }

    /**
     * Sets the {@code PAdESExternalCMSSignatureService}
     *
     * @param service {@link PAdESWithExternalCMSService}
     */
    public void setService(PAdESWithExternalCMSService service) {
        this.service = service;
    }

    @Override
    public DigestDTO getMessageDigest(final RemoteDocument toSignDocument, final RemoteSignatureParameters parameters) {
        Objects.requireNonNull(service, "PAdESExternalCMSSignatureService must be defined!");
        Objects.requireNonNull(toSignDocument, "toSignDocument must be defined!");
        Objects.requireNonNull(parameters, "Parameters must be defined!");
        assertPAdESParameters(parameters);
        LOG.info("GetMessageDigest in process...");

        DSSDocument document = RemoteDocumentConverter.toDSSDocument(toSignDocument);
        PAdESSignatureParameters padesParameters = (PAdESSignatureParameters) createParameters(parameters);
        Digest digestToSign = service.getMessageDigest(document, padesParameters);

        LOG.info("GetMessageDigest is finished");
        return DTOConverter.toDigestDTO(digestToSign);
    }

    @Override
    public RemoteDocument signDocument(final RemoteDocument toSignDocument, final RemoteSignatureParameters parameters,
                                       final RemoteDocument cmsSignature) {
        Objects.requireNonNull(service, "PAdESExternalCMSSignatureService must be defined!");
        Objects.requireNonNull(toSignDocument, "toSignDocument must be defined!");
        Objects.requireNonNull(parameters, "Parameters must be defined!");
        assertPAdESParameters(parameters);
        LOG.info("SignDocument in process...");

        DSSDocument document = RemoteDocumentConverter.toDSSDocument(toSignDocument);
        PAdESSignatureParameters padesParameters = (PAdESSignatureParameters) createParameters(parameters);
        DSSDocument cmsDocument = RemoteDocumentConverter.toDSSDocument(cmsSignature);
        DSSDocument signedDocument = service.signDocument(document, padesParameters, cmsDocument);

        LOG.info("SignDocument is finished");
        return RemoteDocumentConverter.toRemoteDocument(signedDocument);
    }

    private void assertPAdESParameters(RemoteSignatureParameters parameters) {
        Objects.requireNonNull(parameters.getSignatureLevel(), "signatureLevel must be defined!");
        if (!SignatureForm.PAdES.equals(parameters.getSignatureLevel().getSignatureForm())) {
            throw new UnsupportedOperationException("PAdES signature form is required! " +
                    "Please update SignatureLevel within parameters.");
        }
    }

}
