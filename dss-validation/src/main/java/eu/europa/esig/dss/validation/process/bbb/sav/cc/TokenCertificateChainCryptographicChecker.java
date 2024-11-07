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

import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;

import java.util.Date;

/**
 * This class is used to validate the use of cryptographic constraints within the token's certificate chain
 *
 */
public class TokenCertificateChainCryptographicChecker extends CertificateChainCryptographicChecker {

    /**
     * Common constructor
     *
     * @param i18nProvider the access to translation
     * @param token {@link TokenProxy}
     * @param validationTime {@link Date}
     * @param context {@link Context}
     * @param position {@link MessageTag}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public TokenCertificateChainCryptographicChecker(final I18nProvider i18nProvider,  final TokenProxy token,
                                                     final Date validationTime, final Context context,
                                                     final MessageTag position, final ValidationPolicy validationPolicy) {
        super(i18nProvider, token.getSigningCertificate(), token.getCertificateChain(), validationTime, context, position, validationPolicy);
    }

}
