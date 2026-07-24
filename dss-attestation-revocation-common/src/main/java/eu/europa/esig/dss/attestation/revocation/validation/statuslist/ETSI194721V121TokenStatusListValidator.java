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
package eu.europa.esig.dss.attestation.revocation.validation.statuslist;

import eu.europa.esig.dss.attestation.revocation.validation.AttestationRevocationValidator;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.attestation.claim.ClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Validates EAA revocation, with a declared structure as defined in ETSI TS 119 472-1 v1.2.1 "5.2.10 EAA revocation service".
 *
 */
public class ETSI194721V121TokenStatusListValidator implements AttestationRevocationValidator {

    /** Token Status List as specified in IETF draft-ietf-oauth-revocation-list-13 */
    private static final String TOKEN_STATUS_LIST = "TokenStatusList";

    /**
     * Default constructor
     */
    public ETSI194721V121TokenStatusListValidator() {
        // empty
    }

    @Override
    public boolean isSupported(Attestation attestation) {
        return attestation.getPayload() != null && attestation.getPayload().getStatus() != null
                && attestation.getPayload().getStatus().getType() != null
                && TOKEN_STATUS_LIST.equals(attestation.getPayload().getStatus().getType().getStringValue());
    }

    @Override
    public List<String> getUris(Attestation attestation) {
        if (!isSupported(attestation)) {
            throw new UnsupportedOperationException("The provided EAA token does not contain 'revocation' or not supported!");
        }
        ClaimString uriClaim = attestation.getPayload().getStatus().getUri();
        if (uriClaim != null && Utils.isStringNotEmpty(uriClaim.getStringValue())) {
            return Collections.singletonList(uriClaim.getStringValue());
        } else {
            throw new DSSException("No 'uri' claim is present for the 'TokenStatusList' claim!");
        }
    }

    @Override
    public AttestationRevocationToken validate(Attestation attestation, byte[] statusListDocument) {
        if (!isSupported(attestation)) {
            throw new UnsupportedOperationException("The provided EAA token does not contain 'revocation' or not supported!");
        }
        ClaimNumber indexClaim = attestation.getPayload().getStatus().getIndex();
        if (indexClaim != null && indexClaim.getNumberValue() != null) {
            int eaaIndex = indexClaim.getNumberValue().intValue();

            ServiceLoader<StatusListValidatorFactory> loader = ServiceLoader.load(StatusListValidatorFactory.class);
            Iterator<StatusListValidatorFactory> validatorOptions = loader.iterator();

            if (validatorOptions.hasNext()) {
                for (StatusListValidatorFactory factory : loader) {
                    if (factory.isSupported(statusListDocument)) {
                        TokenStatusListValidator tokenStatusListValidator = factory.create(statusListDocument);
                        return tokenStatusListValidator.getRevocationToken(eaaIndex);
                    }
                }
            }
            throw new UnsupportedOperationException("Status document format not recognized/handled");

        } else {
            throw new DSSException("No 'index' claim is present for the 'revocation' claim!");
        }
    }

}
