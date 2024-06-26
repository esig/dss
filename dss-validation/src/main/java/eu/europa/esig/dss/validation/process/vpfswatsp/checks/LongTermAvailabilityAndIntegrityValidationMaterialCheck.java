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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks;


import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class verifies whether the term availability and integrity of validation material
 * is present within the signature
 *
 */
public class LongTermAvailabilityAndIntegrityValidationMaterialCheck extends ChainItem<XmlValidationProcessArchivalData> {

    /** Signature to be verified */
    private final SignatureWrapper signature;

    /** Long-term validation's conclusion */
    private final XmlConstraintsConclusion longTermValidationResult;

    /** LTV Indication */
    private Indication ltvIndication;

    /** LTV SubIndication */
    private SubIndication ltvSubIndication;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessArchivalData}
     * @param signature {@link SignatureWrapper} to be validated
     * @param constraint {@link LevelConstraint}
     */
    public LongTermAvailabilityAndIntegrityValidationMaterialCheck(I18nProvider i18nProvider,
            XmlValidationProcessArchivalData result, SignatureWrapper signature,
            XmlConstraintsConclusion longTermValidationResult, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.signature = signature;
        this.longTermValidationResult = longTermValidationResult;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.LTA;
    }

    @Override
    protected boolean process() {
        if (longTermValidationResult != null && longTermValidationResult.getConclusion() != null) {
            ltvIndication = longTermValidationResult.getConclusion().getIndication();
            ltvSubIndication = longTermValidationResult.getConclusion().getSubIndication();
        }
        return ValidationProcessUtils.isLongTermAvailabilityAndIntegrityMaterialPresent(signature);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ARCH_LTAIVMP;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ARCH_LTAIVMP_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return ltvIndication;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return ltvSubIndication;
    }

    @Override
    protected List<XmlMessage> getPreviousErrors() {
        if (longTermValidationResult != null && longTermValidationResult.getConclusion() != null) {
            List<XmlMessage> errors = new ArrayList<>(longTermValidationResult.getConclusion().getErrors());
            if (Utils.isCollectionNotEmpty(errors)) {
                errors.add(buildErrorMessage());
            }
            return errors;
        }
        return Collections.emptyList();
    }

}
