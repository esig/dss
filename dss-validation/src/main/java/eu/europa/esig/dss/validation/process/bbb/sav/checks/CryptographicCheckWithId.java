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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicRules;

import java.util.Date;

/**
 * This class verifies the result of a cryptographic validation process for the given token,
 * providing its Identifier in the report
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class CryptographicCheckWithId<T extends XmlConstraintsConclusion> extends CryptographicCheck<T> {

    /** Token, which certificate chain will be validated */
    private final TokenProxy token;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param token {@link TokenProxy}
     * @param position {@link MessageTag}
     * @param validationDate {@link Date}
     * @param constraint {@link CryptographicRules}
     */
    public CryptographicCheckWithId(I18nProvider i18nProvider, T result, TokenProxy token, MessageTag position,
                                    Date validationDate, CryptographicRules constraint) {
        super(i18nProvider, result, token, position, validationDate, constraint, token.getId());
        this.token = token;
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.ACCM_DESC_WITH_ID_RESULT, super.buildAdditionalInfo(), token.getId());
    }

}
