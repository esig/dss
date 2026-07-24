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
package eu.europa.esig.dss.ws.attestation.creation.common.builder;

import eu.europa.esig.dss.attestation.common.creation.KeyBindingParameters;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTKeyBindingParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocKeyBindingParameters;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.attestation.creation.common.converter.MdocClaimFromDTOConverter;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters;

import java.util.Objects;

/**
 * Builds {@code KeyBindingParameters} from {@link RemoteKeyBindingParameters}
 *
 */
public class RemoteKeyBindingParametersBuilder {

    /** DTO representing the signature parameters */
    private final RemoteKeyBindingParameters remoteKeyBindingParameters;

    /**
     * Default constructor
     *
     * @param remoteKeyBindingParameters {@link RemoteKeyBindingParameters}
     */
    public RemoteKeyBindingParametersBuilder(final RemoteKeyBindingParameters remoteKeyBindingParameters) {
        Objects.requireNonNull(remoteKeyBindingParameters, "RemoteKeyBindingParameters must be defined!");
        Objects.requireNonNull(remoteKeyBindingParameters.getEaaType(), "EAA type must be definedy!");
        this.remoteKeyBindingParameters = remoteKeyBindingParameters;
    }

    /**
     * Builds the {@code KeyBindingParameters}
     *
     * @return {@link KeyBindingParameters}
     */
    public KeyBindingParameters build() {
        KeyBindingParameters keyBindingParameters;
        switch (remoteKeyBindingParameters.getEaaType()) {
            case SD_JWT_VC:
                keyBindingParameters = buildSDJWTVCKeyBindingParameters(remoteKeyBindingParameters);
                break;
            case ISO_IEC_MDOC:
                keyBindingParameters = buildMdocKeyBindingParameters(remoteKeyBindingParameters);
                break;
            default:
                throw new UnsupportedOperationException(String.format("Unsupported EAA format: '%s'. " +
                        "SD-JWT VC and ISO/IEC mdoc are only supported.", remoteKeyBindingParameters.getEaaType()));
        }
        return keyBindingParameters;
    }

    /**
     * Builds an instance of {@code SDJWTKeyBindingParameters} from the DTO configuration
     *
     * @param remoteKeyBindingParameters {@link RemoteKeyBindingParameters}
     * @return {@link SDJWTKeyBindingParameters}
     */
    protected SDJWTKeyBindingParameters buildSDJWTVCKeyBindingParameters(RemoteKeyBindingParameters remoteKeyBindingParameters) {
        final SDJWTKeyBindingParameters keyBindingParameters = new SDJWTKeyBindingParameters();
        if (remoteKeyBindingParameters.getDigestAlgorithm() != null) {
            keyBindingParameters.setDigestAlgorithm(remoteKeyBindingParameters.getDigestAlgorithm());
        }
        if (remoteKeyBindingParameters.getIssuanceTime() != null) {
            keyBindingParameters.setIssuanceTime(remoteKeyBindingParameters.getIssuanceTime());
        }
        if (remoteKeyBindingParameters.getAudience() != null) {
            keyBindingParameters.setAudience(remoteKeyBindingParameters.getAudience());
        }
        if (remoteKeyBindingParameters.getNonce() != null) {
            keyBindingParameters.setNonce(remoteKeyBindingParameters.getNonce());
        }
        return keyBindingParameters;
    }

    /**
     * Builds an instance of {@code MdocKeyBindingParameters} from the DTO configuration
     *
     * @param remoteKeyBindingParameters {@link RemoteKeyBindingParameters}
     * @return {@link MdocKeyBindingParameters}
     */
    protected MdocKeyBindingParameters buildMdocKeyBindingParameters(RemoteKeyBindingParameters remoteKeyBindingParameters) {
        final MdocKeyBindingParameters keyBindingParameters = new MdocKeyBindingParameters();
        if (remoteKeyBindingParameters.getSessionTranscript() != null) {
            keyBindingParameters.setSessionTranscript(RemoteDocumentConverter.toDSSDocument(remoteKeyBindingParameters.getSessionTranscript()));
        }
        if (remoteKeyBindingParameters.getDocType() != null) {
            keyBindingParameters.setDocType(remoteKeyBindingParameters.getDocType());
        }
        if (remoteKeyBindingParameters.getDeviceSignedDataElements() != null && !remoteKeyBindingParameters.getDeviceSignedDataElements().isEmpty()) {
            final MdocClaimFromDTOConverter converter = new MdocClaimFromDTOConverter();
            remoteKeyBindingParameters.getDeviceSignedDataElements().forEach(c -> keyBindingParameters.addDeviceSignedDataElement(converter.apply(c)));
        }
        return keyBindingParameters;
    }

}
