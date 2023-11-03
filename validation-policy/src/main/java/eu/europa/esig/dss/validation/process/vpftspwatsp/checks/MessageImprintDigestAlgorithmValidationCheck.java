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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Verifies whether the result of {@code MessageImprintDigestAlgorithmValidation} is valid
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class MessageImprintDigestAlgorithmValidationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The timestamp to check */
    private final TimestampWrapper timestamp;

    /** Message-imprint Digest Algorithm validation result */
    private final XmlSAV davResult;

    /** Defined the validation time */
    private final Date currentTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param timestamp {@link TimestampWrapper}
     * @param davResult {@link XmlSAV}
     * @param currentTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public MessageImprintDigestAlgorithmValidationCheck(I18nProvider i18nProvider, T result,
                                                  TimestampWrapper timestamp,
                                                  XmlSAV davResult, Date currentTime,
                                                  LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.timestamp = timestamp;
        this.davResult = davResult;
        this.currentTime = currentTime;
    }

    @Override
    protected boolean process() {
        return isValid(davResult);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ARCH_ICHFCRLPOET;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ARCH_ICHFCRLPOET_ANS;
    }

    @Override
    protected String buildAdditionalInfo() {
        String dateTime = ValidationProcessUtils.getFormattedDate(currentTime);
        if (isValid(davResult)) {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_ID,
                    timestamp.getMessageImprint().getDigestMethod(), dateTime, MessageTag.ACCM_POS_MESS_IMP, timestamp.getId());
        } else {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_ID,
                    timestamp.getMessageImprint().getDigestMethod(), dateTime, MessageTag.ACCM_POS_MESS_IMP, timestamp.getId());
        }
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return davResult.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return davResult.getConclusion().getSubIndication();
    }

}
