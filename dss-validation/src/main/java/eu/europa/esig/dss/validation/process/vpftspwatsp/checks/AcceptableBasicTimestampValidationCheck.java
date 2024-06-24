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
package eu.europa.esig.dss.validation.process.vpftspwatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Collections;
import java.util.List;

/**
 * Checks if a result of a Basic Signature Validation process for a timestamp token is acceptable
 * 
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class AcceptableBasicTimestampValidationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Signature's basic validation conclusion */
    private final XmlConstraintsConclusion basicTimestampValidation;

    /** The validation Indication */
    private Indication bbbIndication;

    /** The validation SubIndication */
    private SubIndication bbbSubIndication;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param basicTimestampValidation {@link XmlConstraintsConclusion}
     * @param constraint {@link LevelConstraint}
     */
    public AcceptableBasicTimestampValidationCheck(I18nProvider i18nProvider, T result,
                                                   XmlConstraintsConclusion basicTimestampValidation,
                                                   LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.basicTimestampValidation = basicTimestampValidation;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.TST_BBB;
    }

    @Override
    protected boolean process() {
        if (basicTimestampValidation != null && basicTimestampValidation.getConclusion() != null) {
            XmlConclusion conclusion = basicTimestampValidation.getConclusion();
            bbbIndication = conclusion.getIndication();
            bbbSubIndication = conclusion.getSubIndication();

            return ValidationProcessUtils.isAllowedBasicTimestampValidation(conclusion);
        }
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ARCH_IRTVBBA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ARCH_IRTVBBA_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return bbbIndication;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return bbbSubIndication;
    }

    @Override
    protected List<XmlMessage> getPreviousErrors() {
        if (basicTimestampValidation != null && basicTimestampValidation.getConclusion() != null) {
            return basicTimestampValidation.getConclusion().getErrors();
        }
        return Collections.emptyList();
    }

}
