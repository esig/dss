package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.attestation.common.creation.AttestationService;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;

/**
 * Abstract implementation of an attestation creation service, containing common methods
 *
 */
public abstract class AbstractRemoteAttestationCreationService {

    /**
     * SD-JWT service
     */
    private SDJWTService sdjwtService;

    /**
     * Mdoc attestation service
     */
    private MdocService mdocService;

    /**
     * Default constructor
     */
    protected AbstractRemoteAttestationCreationService() {
        // empty
    }

    /**
     * Sets the SD-JWT attestation service
     *
     * @param sdjwtService {@link SDJWTService}
     */
    public void setSdjwtService(SDJWTService sdjwtService) {
        this.sdjwtService = sdjwtService;
    }

    /**
     * Sets the mdoc service
     *
     * @param mdocService {@link MdocService}
     */
    public void setMdocService(MdocService mdocService) {
        this.mdocService = mdocService;
    }

    /**
     * Gets the applicable attestation service for the given attestation form
     *
     * @param attestationForm {@link AttestationForm}
     * @return {@link AttestationService}
     */
    @SuppressWarnings("rawtypes")
    protected AttestationService getAttestationServiceForType(AttestationForm attestationForm) {
        AttestationService attestationService;
        switch (attestationForm) {
            case SD_JWT:
                attestationService = sdjwtService;
                break;
            case MDOC:
                attestationService = mdocService;
                break;
            default:
                throw new UnsupportedOperationException(String.format(
                        "Unsupported attestation format: '%s'. SD-JWT and ISO/IEC mdoc are only supported.", attestationForm));
        }
        if (attestationService == null) {
            throw new NullPointerException(String.format("No service has been provided for the attestation form '%s'", attestationForm));
        }
        return attestationService;
    }

    /**
     * Transforms {@code SignatureValueDTO} to {@code SignatureValue}
     *
     * @param signatureValueDTO {@link SignatureValueDTO}
     * @return {@link SignatureValue}
     */
    protected SignatureValue toSignatureValue(SignatureValueDTO signatureValueDTO) {
        return new SignatureValue(signatureValueDTO.getAlgorithm(), signatureValueDTO.getValue());
    }

}
