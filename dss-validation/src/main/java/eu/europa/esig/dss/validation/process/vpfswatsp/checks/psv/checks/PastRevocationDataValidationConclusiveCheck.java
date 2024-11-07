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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if an acceptable revocation data is found
 *
 */
public class PastRevocationDataValidationConclusiveCheck extends ChainItem<eu.europa.esig.dss.detailedreport.jaxb.XmlPSV> {

    /** The validation conclusion */
    private final XmlConclusion conclusion;

    /**
     * Constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the results
     * @param conclusion {@link XmlConclusion}
     * @param constraint {@link LevelConstraint}
     */
    public PastRevocationDataValidationConclusiveCheck(I18nProvider i18nProvider, XmlPSV result,
                                                       XmlConclusion conclusion,
                                                       LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.conclusion = conclusion;
    }

    @Override
    protected boolean process() {
        return isValidConclusion(conclusion);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PSV_DIURDSCHPVR;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.PSV_DIURDSCHPVR_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return conclusion.getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return conclusion.getSubIndication();
    }

}
