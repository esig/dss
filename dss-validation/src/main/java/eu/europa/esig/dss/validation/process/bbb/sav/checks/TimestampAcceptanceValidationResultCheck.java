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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;

/**
 * This class verifies output of "5.2.8 Signature Acceptance Validation" with a timestamp provided as the input
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class TimestampAcceptanceValidationResultCheck<T extends XmlConstraintsConclusion> extends SignatureAcceptanceValidationResultCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       the result
     * @param savResult    {@link XmlSAV}
     * @param constraint   {@link LevelRule}
     */
    public TimestampAcceptanceValidationResultCheck(I18nProvider i18nProvider, T result, XmlSAV savResult, LevelRule constraint) {
        super(i18nProvider, result, savResult, constraint);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_TAV_ISVA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_TAV_ISVA_ANS;
    }

}
