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
package eu.europa.esig.dss.validation.process.eaa.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies whether the EAA has been created with a single signature
 *
 */
public class AttestationSignatureUnicityCheck extends ChainItem<XmlFC> {

    /** EAA to check */
    private final AttestationWrapper eaa;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param eaa {@link AttestationWrapper}
     * @param constraint {@link LevelRule}
     */
    public AttestationSignatureUnicityCheck(I18nProvider i18nProvider, XmlFC result,
                                            AttestationWrapper eaa, LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.eaa = eaa;
    }

    @Override
    protected boolean process() {
        // TODO : to be implemented in TS 119 472-1. Verify the check later
        return Utils.collectionSize(eaa.getEAASignatures()) == 1;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_SIG_PRESENT;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_SIG_PRESENT_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

}
