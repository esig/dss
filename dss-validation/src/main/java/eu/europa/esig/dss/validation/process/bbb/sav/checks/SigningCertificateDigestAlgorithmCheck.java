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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.DigestCryptographicChecker;

import java.util.Date;

/**
 * Verifies a DigestAlgorithm used for a signing-certificate-reference
 *
 * @param <T> implementation of the block's conclusion
 */
public class SigningCertificateDigestAlgorithmCheck<T extends XmlConstraintsConclusion> extends
        SigningCertificateRefDigestCryptographicCheckerResultCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider          {@link I18nProvider}
     * @param result                the result
     * @param validationDate        {@link Date}
     * @param certificateRefWrapper {@link CertificateRefWrapper}
     * @param cryptographicConstraint {@link CryptographicConstraint}
     * @param constraint            {@link LevelConstraint}
     */
    public SigningCertificateDigestAlgorithmCheck(I18nProvider i18nProvider, CertificateRefWrapper certificateRefWrapper,
                                                  T result, Date validationDate, CryptographicConstraint cryptographicConstraint,
                                                  LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, certificateRefWrapper,
                execute(i18nProvider, certificateRefWrapper.getDigestMethod(), validationDate, cryptographicConstraint), constraint);
    }

    private static XmlCC execute(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm, Date validationDate,
                                 CryptographicConstraint constraint) {
        DigestCryptographicChecker dac = new DigestCryptographicChecker(i18nProvider, digestAlgorithm, validationDate,
                MessageTag.ACCM_POS_SIG_CERT_REF, constraint);
        return dac.execute();
    }

}
