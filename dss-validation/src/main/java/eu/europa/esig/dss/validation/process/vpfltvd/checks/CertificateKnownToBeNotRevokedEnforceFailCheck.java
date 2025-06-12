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
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.LevelRule;

import java.util.Date;

/**
 * This check returns information whether the signing-certificate is known to not be revoked and revocation data is acceptable,
 * but always returns the Basic Signature Validation conclusion.
 *
 */
public class CertificateKnownToBeNotRevokedEnforceFailCheck extends CertificateKnownToBeNotRevokedCheck<XmlValidationProcessLongTermData> {

    /**
     * Default constructor
     *
     * @param i18nProvider                  {@link I18nProvider}
     * @param result                        {@link XmlConstraintsConclusion}
     * @param certificate                   {@link CertificateWrapper}
     * @param revocationData                {@link CertificateRevocationWrapper}
     * @param isRevocationDataIssuerTrusted whether the revocation issuer is trusted
     * @param currentTime                   {@link Date}
     * @param bsConclusion                  {@link XmlConclusion}
     * @param constraint                    {@link LevelRule}
     */
    public CertificateKnownToBeNotRevokedEnforceFailCheck(I18nProvider i18nProvider,
            XmlValidationProcessLongTermData result, CertificateWrapper certificate, CertificateRevocationWrapper revocationData,
            boolean isRevocationDataIssuerTrusted, Date currentTime, XmlConclusion bsConclusion, LevelRule constraint) {
        super(i18nProvider, result, certificate, revocationData, isRevocationDataIssuerTrusted, currentTime, bsConclusion, constraint);
    }

    @Override
    protected boolean process() {
        return false;
    }

}
