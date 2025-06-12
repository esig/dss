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
package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies if the identification of the signing certificate (as per clause 5.2.3) succeeded
 *
 * @param <T> implementation of the block's conclusion
 */
public class IdentificationOfSigningCertificateResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Identification of Signing Certificate building block suffix */
    private static final String ISC_BLOCK_SUFFIX = "-ISC";

    /** Identification of the Signing Certificate building block result */
    private final XmlISC xmlISC;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param xmlISC {@link XmlISC}
     * @param token {@link TokenProxy}
     * @param constraint {@link LevelRule}
     */
    public IdentificationOfSigningCertificateResultCheck(I18nProvider i18nProvider, T result,
                                                         XmlISC xmlISC, TokenProxy token, LevelRule constraint) {
        super(i18nProvider, result, constraint, token.getId() + ISC_BLOCK_SUFFIX);
        this.xmlISC = xmlISC;
    }

    @Override
    protected boolean process() {
        return xmlISC != null && isValid(xmlISC);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.NO_SIGNING_CERTIFICATE_FOUND;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_IISCRC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_IISCRC_ANS;
    }

}
