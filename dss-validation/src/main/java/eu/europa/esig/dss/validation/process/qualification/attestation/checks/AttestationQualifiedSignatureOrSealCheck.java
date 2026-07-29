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
package eu.europa.esig.dss.validation.process.qualification.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationAttestationQualificationProcess;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class is used to verify whether the attestation has been created with
 * a qualified electronic signature or seal
 *
 */
public class AttestationQualifiedSignatureOrSealCheck extends ChainItem<XmlValidationAttestationQualificationProcess> {

    /** Signature to be checked */
    private final SignatureWrapper signature;

    /** The Signature Qualification to be checked */
    private final SignatureQualification signatureQualification;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationAttestationQualificationProcess}
     * @param signature {@link SignatureWrapper}
     * @param signatureQualification {@link SignatureQualification}
     * @param constraint {@link LevelRule}
     */
    public AttestationQualifiedSignatureOrSealCheck(I18nProvider i18nProvider, XmlValidationAttestationQualificationProcess result,
                                                    SignatureWrapper signature, SignatureQualification signatureQualification,
                                                    LevelRule constraint) {
        super(i18nProvider, result, constraint);

        this.signature = signature;
        this.signatureQualification = signatureQualification;
    }

    @Override
    protected boolean process() {
        // Indeterminate statuses are handled separately
        return SignatureQualification.QESIG == signatureQualification || SignatureQualification.QESEAL == signatureQualification ||
                SignatureQualification.INDETERMINATE_QESIG == signatureQualification || SignatureQualification.INDETERMINATE_QESEAL == signatureQualification;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_SIG_QUAL;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_SIG_QUAL_ANS;
    }

    @Override
    protected XmlMessage buildErrorMessage() {
        return buildXmlMessage(getErrorMessageTag(), signatureQualification.getReadable());
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.SIGNATURE_ID, signature.getId());
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
