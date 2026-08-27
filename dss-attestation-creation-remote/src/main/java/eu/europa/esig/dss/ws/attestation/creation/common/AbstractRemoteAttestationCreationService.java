/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
