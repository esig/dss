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
package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies if the Validation Context Initialization as per clause 5.2.4 succeeded
 *
 * @param <T> implementation of the block's conclusion
 */
public class ValidationContextInitializationResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Validation Context Initialization building block suffix */
    private static final String VCI_BLOCK_SUFFIX = "-VCI";

    /** Validation Context Initialization result */
    private final XmlVCI xmlVCI;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param xmlVCI {@link XmlVCI}
     * @param token {@link TokenProxy}
     * @param constraint {@link LevelConstraint}
     */
    public ValidationContextInitializationResultCheck(I18nProvider i18nProvider, T result,
                                                      XmlVCI xmlVCI, TokenProxy token, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + VCI_BLOCK_SUFFIX);
        this.xmlVCI = xmlVCI;
    }

    @Override
    protected boolean process() {
        return xmlVCI != null && isValid(xmlVCI);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return xmlVCI.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return xmlVCI.getConclusion().getSubIndication();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_IVCIRC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_IVCIRC_ANS;
    }

}
