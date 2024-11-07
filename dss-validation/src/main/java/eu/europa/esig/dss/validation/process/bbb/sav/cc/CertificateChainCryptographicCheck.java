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
package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheckerResultCheck;

import java.util.Date;

/**
 * This class is used to verify a validation result of a cryptograpic validation process for a signature's certificate chain
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class CertificateChainCryptographicCheck<T extends XmlConstraintsConclusion> extends CryptographicCheckerResultCheck<T> {

    /**
     * Default constructor to create a CertificateChainCryptographicCheck
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param validationDate {@link Date}
     * @param position {@link MessageTag}
     * @param ccResult {@link XmlCC}
     * @param constraint {@link LevelConstraint}
     */
    public CertificateChainCryptographicCheck(final I18nProvider i18nProvider, final T result,
                                              final Date validationDate, final MessageTag position, final XmlCC ccResult,
                                              final LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, position, ccResult, constraint);
    }

    /**
     * Constructor to create a CertificateChainCryptographicCheck with a defined token's id
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param token {@link TokenProxy}
     * @param validationDate {@link Date}
     * @param position {@link MessageTag}
     * @param ccResult {@link XmlCC}
     * @param constraint {@link LevelConstraint}
     */
    protected CertificateChainCryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token,
                                                 Date validationDate, MessageTag position, XmlCC ccResult,
                                                 LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, position, ccResult, constraint, token.getId());
    }

}
