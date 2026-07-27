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
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.AttestationRevocationTokenWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Date;

/**
 * Performs cryptographic validation of the attestation revocation token and its certificate chain
 *
 */
public class AttestationRevocationAlgorithmObsolescenceValidation extends TokenAlgorithmObsolescenceValidation<AttestationRevocationTokenWrapper> {

    /**
     * Common constructor
     *
     * @param i18nProvider     the access to translations
     * @param token            instance of {@link AbstractTokenProxy} to be processed
     * @param validationDate   {@link Date} validation time
     * @param validationPolicy {@link ValidationPolicy} to be used during the validation
     */
    public AttestationRevocationAlgorithmObsolescenceValidation(I18nProvider i18nProvider, AttestationRevocationTokenWrapper token,
                                                                Date validationDate, ValidationPolicy validationPolicy) {
        super(i18nProvider, token, Context.ATTESTATION_REVOCATION, validationDate, validationPolicy);
    }

    @Override
    protected ChainItem<XmlAOV> buildChain() {

        ChainItem<XmlAOV> item = super.buildChain();

        item = buildCertificateChainValidationChain(item, token.getSigningCertificate(), token.getCertificateChain());

        return item;

    }

}
