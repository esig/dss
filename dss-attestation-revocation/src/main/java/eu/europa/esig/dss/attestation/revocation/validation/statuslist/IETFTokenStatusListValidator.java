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
import eu.europa.esig.dss.attestation.revocation.x509.AttestationRevocationListCertificateSource;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Performs validation of the attestation revocation using the Token Status List mechanism, as defined in
 * <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-20.html">IETF Token Status List (TSL)</a>.
 *
 */
public class IETFTokenStatusListValidator implements AttestationRevocationValidator {

    /**
     * Default constructor
     */
    public IETFTokenStatusListValidator() {
        // empty
    }

    @Override
    public boolean isSupported(Attestation attestation) {
        return attestation.getPayload() != null && attestation.getPayload().getStatus() != null && attestation.getPayload().getStatus().getStatusList() != null;
    }

    @Override
    public List<String> getUris(Attestation attestation) {
        if (!isSupported(attestation)) {
            throw new UnsupportedOperationException("The provided attestation token does not contain 'status_list' or not supported!");
        }
        VerifiedClaimString uriClaim = attestation.getPayload().getStatus().getStatusList().getUri();
        if (uriClaim != null && Utils.isStringNotEmpty(uriClaim.getStringValue())) {
            return Collections.singletonList(uriClaim.getStringValue());
        } else {
            throw new DSSException("No 'uri' claim is present for the 'status_list' claim!");
        }
    }

    @Override
    public AttestationRevocationToken validate(Attestation attestation, byte[] statusListDocument) {
        if (!isSupported(attestation)) {
            throw new UnsupportedOperationException("The provided attestation token does not contain 'status_list' or not supported!");
        }
        VerifiedClaimNumber indexClaim = attestation.getPayload().getStatus().getStatusList().getIndex();
        if (indexClaim != null && indexClaim.getNumberValue() != null) {
            int attestationIndex = indexClaim.getNumberValue().intValue();

            ServiceLoader<TokenStatusListValidatorFactory> loader = ServiceLoader.load(TokenStatusListValidatorFactory.class);
            Iterator<TokenStatusListValidatorFactory> validatorOptions = loader.iterator();

            if (validatorOptions.hasNext()) {
                for (TokenStatusListValidatorFactory factory : loader) {
                    if (factory.isSupported(statusListDocument)) {
                        TokenStatusListValidator tokenStatusListValidator = factory.create(statusListDocument);
                        AttestationRevocationToken statusToken = tokenStatusListValidator.getRevocationToken(attestationIndex);
                        statusToken.setCertificateSource(getCertificateSource(attestation));
                        return statusToken;
                    }
                }
            }
            throw new UnsupportedOperationException("Status document format not recognized/handled");

        } else {
            throw new DSSException("No 'idx' claim is present for the 'status_list' claim!");
        }
    }

    /**
     * Gets the certificate source based on the certificate present within the "status_list" claim, if any
     *
     * @param attestation {@link Attestation}
     * @return {@link TokenCertificateSource}
     */
    protected TokenCertificateSource getCertificateSource(Attestation attestation) {
        return new AttestationRevocationListCertificateSource(attestation.getPayload().getStatus().getStatusList());
    }

}
