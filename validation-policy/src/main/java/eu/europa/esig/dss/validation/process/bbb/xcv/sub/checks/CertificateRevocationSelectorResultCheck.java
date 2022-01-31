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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * This class verifies the result of a {@code CertificateRevocationSelector}
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class CertificateRevocationSelectorResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** CRS result */
    protected final XmlCRS crsResult;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param crsResult {@link XmlCRS}
     * @param constraint {@link LevelConstraint}
     */
    public CertificateRevocationSelectorResultCheck(I18nProvider i18nProvider, T result, XmlCRS crsResult,
                                                 LevelConstraint constraint) {
        super(i18nProvider, result, constraint, crsResult.getId());
        this.crsResult = crsResult;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.CRS;
    }

    @Override
    protected boolean process() {
        return isValid(crsResult);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_IARDPFC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_IARDPFC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return crsResult.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return crsResult.getConclusion().getSubIndication();
    }

    @Override
    protected List<XmlMessage> getPreviousErrors() {
        return crsResult.getConclusion().getErrors();
    }

    @Override
    protected String buildAdditionalInfo() {
        if (crsResult.getLatestAcceptableRevocationId() != null) {
            return i18nProvider.getMessage(MessageTag.LAST_ACCEPTABLE_REVOCATION, crsResult.getLatestAcceptableRevocationId());
        }
        return null;
    }

}
