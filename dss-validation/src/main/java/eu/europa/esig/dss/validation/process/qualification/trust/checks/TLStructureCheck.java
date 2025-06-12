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
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValueRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks whether structure of Trusted List is valid
 *
 */
public class TLStructureCheck extends ChainItem<XmlTLAnalysis> {

    /** Trusted List to check */
    private final XmlTrustedList currentTL;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlTLAnalysis}
     * @param currentTl {@link XmlTrustedList}
     * @param constraint {@link ValueRule}
     */
    public TLStructureCheck(I18nProvider i18nProvider, XmlTLAnalysis result, XmlTrustedList currentTl,
                             LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.currentTL = currentTl;
    }

    @Override
    protected boolean process() {
        return currentTL.getStructuralValidation() == null || Utils.isTrue(currentTL.getStructuralValidation().isValid());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QUAL_TL_SV;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QUAL_TL_SV_ANS;
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
