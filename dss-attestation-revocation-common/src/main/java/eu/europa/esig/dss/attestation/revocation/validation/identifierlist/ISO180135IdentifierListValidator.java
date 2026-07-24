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
package eu.europa.esig.dss.attestation.revocation.validation.identifierlist;

import eu.europa.esig.dss.attestation.revocation.validation.AttestationRevocationValidator;
import eu.europa.esig.dss.attestation.revocation.x509.AttestationRevocationListCertificateSource;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.attestation.claim.ClaimByteString;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Verifies EAA's revocation revocation using the Identifier List mechanism as defined
 * in ISO/IEC 18013-5 "12.3.6.4 Identifier list details"
 *
 */
public class ISO180135IdentifierListValidator implements AttestationRevocationValidator {

    /**
     * Default constructor
     */
    public ISO180135IdentifierListValidator() {
        // empty
    }

    @Override
    public boolean isSupported(Attestation attestation) {
        return attestation.getPayload() != null && attestation.getPayload().getStatus() != null && attestation.getPayload().getStatus().getIdentifierList() != null;
    }

    @Override
    public List<String> getUris(Attestation attestation) {
        if (!isSupported(attestation)) {
            throw new UnsupportedOperationException("The provided EAA token does not contain 'identifier_list' or not supported!");
        }
        ClaimString uriClaim = attestation.getPayload().getStatus().getIdentifierList().getUri();
        if (uriClaim != null && Utils.isStringNotEmpty(uriClaim.getStringValue())) {
            return Collections.singletonList(uriClaim.getStringValue());
        } else {
            throw new DSSException("No 'uri' claim is present for the 'identifier_list' claim!");
        }
    }

    @Override
    public AttestationRevocationToken validate(Attestation attestation, byte[] identifierListDocument) {
        if (!isSupported(attestation)) {
            throw new UnsupportedOperationException("The provided EAA token does not contain 'identifier_list' or not supported!");
        }
        ClaimByteString identifier = attestation.getPayload().getStatus().getIdentifierList().getIdentifier();
        if (identifier != null && identifier.getBinaryValue() != null) {
            byte[] identifierBytes = identifier.getBinaryValue();

            ServiceLoader<IdentifierListValidatorFactory> loader = ServiceLoader.load(IdentifierListValidatorFactory.class);
            Iterator<IdentifierListValidatorFactory> validatorOptions = loader.iterator();

            if (validatorOptions.hasNext()) {
                for (IdentifierListValidatorFactory factory : loader) {
                    if (factory.isSupported(identifierListDocument)) {
                        IdentifierListValidator identifierListValidator = factory.create(identifierListDocument);
                        AttestationRevocationToken statusToken = identifierListValidator.getRevocationToken(identifierBytes);
                        statusToken.setCertificateSource(getCertificateSource(attestation));
                        return statusToken;
                    }
                }
            }
            throw new UnsupportedOperationException("Status document format not recognized/handled");

        } else {
            throw new DSSException("No 'id' claim is present for the 'identifier_list' claim!");
        }
    }

    /**
     * Gets the certificate source based on the certificate present within the "status_list" claim, if any
     *
     * @param attestation {@link Attestation}
     * @return {@link TokenCertificateSource}
     */
    protected TokenCertificateSource getCertificateSource(Attestation attestation) {
        return new AttestationRevocationListCertificateSource(attestation.getPayload().getStatus().getIdentifierList());
    }

}
