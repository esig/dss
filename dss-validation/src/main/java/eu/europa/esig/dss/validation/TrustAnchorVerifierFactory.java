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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.spi.validation.TrustAnchorVerifier;

/**
 * This class loads {@code TrustAnchorVerifier} from a provided {@code eu.europa.esig.dss.policy.ValidationPolicy}
 *
 */
public class TrustAnchorVerifierFactory {

    /** Validation policy to load TrustAnchorVerifier from */
    private final ValidationPolicy validationPolicy;

    /**
     * Default constructor
     *
     * @param validationPolicy {@link ValidationPolicy}
     */
    public TrustAnchorVerifierFactory(final ValidationPolicy validationPolicy) {
        this.validationPolicy = validationPolicy;
    }

    /**
     * Creates the {@code TrustAnchorVerifier}
     *
     * @return {@link TrustAnchorVerifier}
     */
    public TrustAnchorVerifier create() {
        final TrustAnchorVerifier trustAnchorVerifier = TrustAnchorVerifier.createEmptyTrustAnchorVerifier();
        instantiateAcceptUntrustedCertificateChains(trustAnchorVerifier, validationPolicy);
        instantiateUseSunsetDate(trustAnchorVerifier, validationPolicy);
        return trustAnchorVerifier;
    }

    private void instantiateAcceptUntrustedCertificateChains(TrustAnchorVerifier trustAnchorVerifier,
                                                             ValidationPolicy validationPolicy) {
        if (validationPolicy.getRevocationConstraints() != null) {
            boolean acceptUntrustedCertificateChains = getAcceptUntrustedCertificateChains(
                    validationPolicy.getRevocationConstraints().getBasicSignatureConstraints());
            trustAnchorVerifier.setAcceptRevocationUntrustedCertificateChains(acceptUntrustedCertificateChains);
        }
        if (validationPolicy.getTimestampConstraints() != null) {
            boolean acceptUntrustedCertificateChains = getAcceptUntrustedCertificateChains(
                    validationPolicy.getTimestampConstraints().getBasicSignatureConstraints());
            trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(acceptUntrustedCertificateChains);
        }
    }

    private boolean getAcceptUntrustedCertificateChains(BasicSignatureConstraints basicSignatureConstraints) {
        if (basicSignatureConstraints != null) {
            LevelConstraint constraint = basicSignatureConstraints.getProspectiveCertificateChain();
            return constraint == null || !Level.FAIL.equals(constraint.getLevel());
        }
        return true;
    }

    private void instantiateUseSunsetDate(TrustAnchorVerifier trustAnchorVerifier, ValidationPolicy validationPolicy) {
        boolean useSunsetDate = false;
        if (validationPolicy.getSignatureConstraints() != null) {
            useSunsetDate = getUseSunsetDate(validationPolicy.getSignatureConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getCounterSignatureConstraints() != null) {
            useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getTimestampConstraints() != null) {
            useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy.getTimestampConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getRevocationConstraints() != null) {
            useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy.getRevocationConstraints().getBasicSignatureConstraints());
        }
        trustAnchorVerifier.setUseSunsetDate(useSunsetDate);
    }

    private boolean getUseSunsetDate(BasicSignatureConstraints basicSignatureConstraints) {
        if (basicSignatureConstraints != null) {
            if (basicSignatureConstraints.getSigningCertificate() != null) {
                LevelConstraint constraint = basicSignatureConstraints.getSigningCertificate().getSunsetDate();
                if (constraint != null && Level.FAIL.equals(constraint.getLevel())) {
                    return true;
                }
            }
            if (basicSignatureConstraints.getCACertificate() != null) {
                LevelConstraint constraint = basicSignatureConstraints.getCACertificate().getSunsetDate();
                if (constraint != null && Level.FAIL.equals(constraint.getLevel())) {
                    return true;
                }
            }
        }
        return false;
    }

}
