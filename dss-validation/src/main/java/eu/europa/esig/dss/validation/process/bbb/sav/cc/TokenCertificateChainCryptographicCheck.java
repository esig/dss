/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
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

import java.util.Date;

public class TokenCertificateChainCryptographicCheck<T extends XmlConstraintsConclusion> extends CertificateChainCryptographicCheck<T> {

    /** Token, which certificate chain will be validated */
    private final TokenProxy token;

    public TokenCertificateChainCryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token,
                                                   Date validationDate, MessageTag position, XmlCC ccResult,
                                                   LevelConstraint constraint) {
        super(i18nProvider, result, token, validationDate, position, ccResult, constraint);
        this.token = token;
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.ACCM_DESC_WITH_ID_RESULT, super.buildAdditionalInfo(), token.getId());
    }

}
