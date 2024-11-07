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
package eu.europa.esig.dss.validation.process.qualification.trust.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TSLTypeEnum;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the Trusted List is defined with MRA
 *
 */
public class TLMRACheck extends ChainItem<XmlTLAnalysis> {

    /** Trusted List to check */
    private final XmlTrustedList currentTL;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlTLAnalysis}
     * @param currentTL {@link XmlTrustedList}
     * @param constraint {@link LevelConstraint}
     */
    public TLMRACheck(I18nProvider i18nProvider, XmlTLAnalysis result, XmlTrustedList currentTL,
                      LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.currentTL = currentTL;
    }

    @Override
    protected boolean process() {
        return currentTL.isMra() == null || !currentTL.isMra();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QUAL_TL_IMRA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        XmlTrustedList parentTL = currentTL.getParent();
        if (parentTL != null) {
            String tslType = parentTL.getTSLType();
            if (TSLTypeEnum.EUlistofthelists.getUri().equals(tslType)) {
                return MessageTag.QUAL_TL_IMRA_ANS_V1;
            } else if (TSLTypeEnum.AdESlistofthelists.getUri().equals(tslType)) {
                return MessageTag.QUAL_TL_IMRA_ANS_V2;
            }
        }
        // default
        return MessageTag.QUAL_TL_IMRA_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

}
