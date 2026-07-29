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
package eu.europa.esig.dss.validation.process.attestation.status;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AttestationRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

/**
 * Verifies whether the attestation revocation token's subject is known
 *
 */
public class AttestationRevocationSubjectCheck extends AbstractMultiValuesCheckItem<XmlSAV> {

    /** attestation revocation token to check */
    private final AttestationRevocationTokenWrapper attestationRevocationToken;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param attestationRevocationToken {@link AttestationRevocationWrapper}
     * @param constraint {@link MultiValuesRule}
     */
    public AttestationRevocationSubjectCheck(I18nProvider i18nProvider, XmlSAV result, AttestationRevocationTokenWrapper attestationRevocationToken,
                                             MultiValuesRule constraint) {
        super(i18nProvider, result, constraint);
        this.attestationRevocationToken = attestationRevocationToken;
    }

    @Override
    protected boolean process() {
        return processValueCheck(attestationRevocationToken.getSubject());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_REV_SUB;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_REV_SUB_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.ATTESTATION_CONSTRAINTS_FAILURE;
    }

}
