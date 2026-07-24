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
package eu.europa.esig.dss.validation.process.bbb.aov;

import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Date;

/**
 * Performs algorithm obsolescence validation for cryptographic algorithms used within an EAA
 *
 */
public class AttestationAlgorithmObsolescenceValidation extends DigestAlgorithmObsolescenceValidation<AttestationWrapper> {

    /**
     * Default constructor
     *
     * @param i18nProvider     the access to translations
     * @param token            instance of {@link AttestationWrapper} to be processed
     * @param validationDate   {@link Date} validation time
     * @param validationPolicy {@link ValidationPolicy} to be used during the validation
     */
    public AttestationAlgorithmObsolescenceValidation(I18nProvider i18nProvider, AttestationWrapper token,
                                                      Date validationDate, ValidationPolicy validationPolicy) {
        super(i18nProvider, token, Context.EAA, validationDate, validationPolicy);
    }

    @Override
    protected ChainItem<XmlAOV> buildChain() {
        return buildDigestMatchersValidationChain(firstItem, token.getDigestMatchers(), token.getId());
    }

    @Override
    protected CryptographicSuite getCryptographicSuite() {
        return validationPolicy.getEAACryptographicConstraint();
    }

}
