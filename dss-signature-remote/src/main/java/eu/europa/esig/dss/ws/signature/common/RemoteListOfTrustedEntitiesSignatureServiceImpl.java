package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.vical.CborVICALSignatureParametersBuilder;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.lote.JsonListOfTrustedEntitiesSignatureParametersBuilder;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParametersBuilder;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteListOfTrustedEntitiesSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.xades.lote.XmlListOfTrustedEntitiesSignatureParametersBuilder;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Implementation of a List of Trusted Entities signing service
 *
 */
public class RemoteListOfTrustedEntitiesSignatureServiceImpl extends AbstractRemoteSignatureServiceImpl
        implements RemoteListOfTrustedEntitiesSignatureService {

    private static final long serialVersionUID = 8878906680078182565L;

    private static final Logger LOG = LoggerFactory.getLogger(RemoteListOfTrustedEntitiesSignatureServiceImpl.class);

    /** XAdES signature service */
    private XAdESService xadesService;

    /** JAdES signature service */
    private JAdESService jadesService;

    /** CB-AdES signature service */
    private CBAdESService cbadesService;

    /**
     * Default constructor
     */
    public RemoteListOfTrustedEntitiesSignatureServiceImpl() {
        // empty
    }

    /**
     * Sets the XAdES signature service
     *
     * @param xadesService {@link XAdESService}
     */
    public void setXadesService(XAdESService xadesService) {
        this.xadesService = xadesService;
    }

    /**
     * Sets the JAdES signature service
     *
     * @param jadesService {@link JAdESService}
     */
    public void setJadesService(JAdESService jadesService) {
        this.jadesService = jadesService;
    }

    /**
     * Sets the CB-AdES signature service
     *
     * @param cbadesService {@link CBAdESService}
     */
    public void setCbadesService(CBAdESService cbadesService) {
        this.cbadesService = cbadesService;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Override
    public ToBeSignedDTO getDataToSign(final RemoteDocument listOfTrustedEntities, final RemoteListOfTrustedEntitiesSignatureParameters parameters) {
        Objects.requireNonNull(listOfTrustedEntities, "List of Trusted Entities must be defined!");
        Objects.requireNonNull(parameters, "Parameters must be defined!");
        Objects.requireNonNull(parameters.getSigningCertificate(), "Signing Certificate must be defined!");
        LOG.info("GetDataToSign in process...");

        DSSDocument loteDocument = RemoteDocumentConverter.toDSSDocument(listOfTrustedEntities);
        SignatureForm signatureForm = getTargetSignatureForm(loteDocument);
        SerializableSignatureParameters signatureParameters = getSignatureParameters(loteDocument, parameters, signatureForm);
        DocumentSignatureService service = getService(signatureForm);
        ToBeSigned dataToSign = service.getDataToSign(loteDocument, signatureParameters);

        LOG.info("GetDataToSign is finished");
        return DTOConverter.toToBeSignedDTO(dataToSign);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Override
    public RemoteDocument signDocument(final RemoteDocument listOfTrustedEntities, final RemoteListOfTrustedEntitiesSignatureParameters parameters,
                                       final SignatureValueDTO signatureValue) {
        Objects.requireNonNull(listOfTrustedEntities, "List of Trusted Entities must be defined!");
        Objects.requireNonNull(parameters, "Parameters must be defined!");
        Objects.requireNonNull(parameters.getSigningCertificate(), "Signing Certificate must be defined!");
        Objects.requireNonNull(signatureValue, "Signature Value must be defined!");
        LOG.info("SignDocument in process...");

        DSSDocument loteDocument = RemoteDocumentConverter.toDSSDocument(listOfTrustedEntities);
        SignatureForm signatureForm = getTargetSignatureForm(loteDocument);
        SerializableSignatureParameters signatureParameters = getSignatureParameters(loteDocument, parameters, signatureForm);
        DocumentSignatureService service = getService(signatureForm);
        DSSDocument signDocument = service.signDocument(loteDocument, signatureParameters, toSignatureValue(signatureValue));

        LOG.info("SignDocument is finished");
        return RemoteDocumentConverter.toRemoteDocument(signDocument);
    }

    /**
     * Gets the target signature form based on the original document's content
     * 
     * @param document {@link DSSDocument} to be signed
     * @return {@link SignatureForm}
     */
    protected SignatureForm getTargetSignatureForm(DSSDocument document) {
        if (DomUtils.startsWithXmlPreamble(document)) {
            return SignatureForm.XAdES;
        } else if (DSSJsonUtils.isJsonDocument(document)) {
            return SignatureForm.JAdES;
        } else if (CBORUtils.isCbor(document)) {
            return SignatureForm.CBAdES;
        }
        throw new UnsupportedOperationException("The document type is not supported!");
    }

    @SuppressWarnings("rawtypes")
    private DocumentSignatureService getService(SignatureForm signatureForm) {
        DocumentSignatureService service;
        switch (signatureForm) {
            case XAdES:
                service = xadesService;
                break;
            case JAdES:
                service = jadesService;
                break;
            case CBAdES:
                service = cbadesService;
                break;
            default:
                throw new UnsupportedOperationException("Unsupported format " + signatureForm);
        }
        if (service == null) {
            throw new NullPointerException(String.format("No service has been provided for the signature form '%s'",
                    signatureForm));
        }
        return service;
    }

    /**
     * Creates parameters for a signature creation (not container)
     *
     * @param document {@link DSSDocument}
     * @param remoteParameters {@link RemoteSignatureParameters}
     * @param signatureForm {@link SignatureForm}
     * @return {@link SerializableSignatureParameters}
     */
    @SuppressWarnings("rawtypes")
    protected SerializableSignatureParameters getSignatureParameters(DSSDocument document, 
            RemoteListOfTrustedEntitiesSignatureParameters remoteParameters, SignatureForm signatureForm) {
        CertificateToken certificateToken = RemoteCertificateConverter.toCertificateToken(remoteParameters.getSigningCertificate());
        AbstractSignatureParametersBuilder parametersBuilder;
        switch (signatureForm) {
            case XAdES:
                XmlListOfTrustedEntitiesSignatureParametersBuilder xmlParametersBuilder =
                        new XmlListOfTrustedEntitiesSignatureParametersBuilder(certificateToken, document);
                if (remoteParameters.getReferenceId() != null) {
                    xmlParametersBuilder.setReferenceId(remoteParameters.getReferenceId());
                }
                if (remoteParameters.getReferenceDigestAlgorithm() != null) {
                    xmlParametersBuilder.setReferenceDigestAlgorithm(remoteParameters.getReferenceDigestAlgorithm());
                }
                parametersBuilder = xmlParametersBuilder;
                break;
                
            case JAdES:
                parametersBuilder = new JsonListOfTrustedEntitiesSignatureParametersBuilder(certificateToken, document);
                break;
                
            case CBAdES:
                parametersBuilder = new CborVICALSignatureParametersBuilder(certificateToken, document);
                break;
                
            default:
                throw new UnsupportedOperationException("Unsupported signature form : " + signatureForm);
        }

        if (remoteParameters.getEncryptionAlgorithm() != null) {
            parametersBuilder.setEncryptionAlgorithm(remoteParameters.getEncryptionAlgorithm());
        }
        if (remoteParameters.getDigestAlgorithm() != null) {
            parametersBuilder.setDigestAlgorithm(remoteParameters.getDigestAlgorithm());
        }
        if (remoteParameters.getBLevelParameters() != null) {
            parametersBuilder.setBLevelParams(toBLevelParameters(remoteParameters.getBLevelParameters()));
        }
        return parametersBuilder.build();
    }

}
