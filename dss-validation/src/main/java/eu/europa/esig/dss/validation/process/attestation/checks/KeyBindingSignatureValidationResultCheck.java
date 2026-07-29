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
package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessAttestation;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.qualification.signature.checks.SignatureValidationResultCheck;

/**
 * Performs verification of the validation result of the key binding signature
 *
 */
public class KeyBindingSignatureValidationResultCheck extends SignatureValidationResultCheck<XmlValidationProcessAttestation> {

    /**
     * Default constructor
     *
     * @param i18nProvider              {@link I18nProvider}
     * @param result                    {@link XmlConstraintsConclusion}
     * @param basicValidationConclusion {@link XmlConclusion}
     * @param constraint                {@link LevelRule}
     */
    public KeyBindingSignatureValidationResultCheck(I18nProvider i18nProvider, XmlValidationProcessAttestation result,
                                                    XmlConclusion basicValidationConclusion, LevelRule constraint) {
        super(i18nProvider, result, basicValidationConclusion, constraint);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_KBRC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_KBRC_ANS;
    }

}
