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

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.validation.TrustAnchorVerifier;

/**
 * This class loads {@code TrustAnchorVerifier} from a provided {@code eu.europa.esig.dss.model.policy.ValidationPolicy}
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
        boolean acceptUntrustedCertificateChains = getAcceptUntrustedCertificateChains(validationPolicy, Context.REVOCATION);
        trustAnchorVerifier.setAcceptRevocationUntrustedCertificateChains(acceptUntrustedCertificateChains);

        acceptUntrustedCertificateChains = getAcceptUntrustedCertificateChains(validationPolicy, Context.TIMESTAMP);
        trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(acceptUntrustedCertificateChains);
    }

    private boolean getAcceptUntrustedCertificateChains(ValidationPolicy validationPolicy, Context context) {
        LevelRule constraint = validationPolicy.getProspectiveCertificateChainConstraint(context);
        return constraint == null || !Level.FAIL.equals(constraint.getLevel());
    }

    private void instantiateUseSunsetDate(TrustAnchorVerifier trustAnchorVerifier, ValidationPolicy validationPolicy) {
        boolean useSunsetDate = getUseSunsetDate(validationPolicy, Context.SIGNATURE);
        useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy, Context.COUNTER_SIGNATURE);
        useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy, Context.TIMESTAMP);
        useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy, Context.REVOCATION);
        trustAnchorVerifier.setUseSunsetDate(useSunsetDate);
    }

    private boolean getUseSunsetDate(ValidationPolicy validationPolicy, Context context) {
        LevelRule constraint = validationPolicy.getCertificateSunsetDateConstraint(context, SubContext.SIGNING_CERT);
        if (constraint != null && Level.FAIL.equals(constraint.getLevel())) {
            return true;
        }
        constraint = validationPolicy.getCertificateSunsetDateConstraint(context, SubContext.CA_CERTIFICATE);
        if (constraint != null && Level.FAIL.equals(constraint.getLevel())) {
            return true;
        }
        return false;
    }

}
