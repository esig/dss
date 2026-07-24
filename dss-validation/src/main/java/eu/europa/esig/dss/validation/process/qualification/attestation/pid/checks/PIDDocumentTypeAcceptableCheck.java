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
package eu.europa.esig.dss.validation.process.qualification.attestation.pid.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationPIDQualificationProcess;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies whether the PID contains person identification data defined within an eIDAS allowed namespace
 *
 */
public class PIDDocumentTypeAcceptableCheck extends ChainItem<XmlValidationPIDQualificationProcess> {

    /** EAA presentation to be checked */
    private final AttestationWrapper eaa;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationPIDQualificationProcess}
     * @param eaa {@link AttestationWrapper}
     * @param constraint {@link LevelRule}
     */
    public PIDDocumentTypeAcceptableCheck(I18nProvider i18nProvider, XmlValidationPIDQualificationProcess result,
                                          AttestationWrapper eaa, LevelRule constraint) {
        super(i18nProvider, result, constraint);

        this.eaa = eaa;
    }

    @Override
    public boolean process() {
        String documentType = getClaimedDocumentType();
        if (documentType == null) {
            return false;
        }
        switch (eaa.getEAAType()) {
            case SD_JWT_VC:
                return documentType.startsWith("urn:eudi:pid:");
            case ISO_IEC_MDOC:
                // TODO : not clear what element is to be checked
                /*
                 * The attestation type for person identification data in ISO/IEC mdoc format
                 * shall be "eu.europa.ec.eudi.pid.1".
                 */
                return documentType.equals("eu.europa.ec.eudi.pid.1");
            default:
                throw new UnsupportedOperationException(String.format("Not supported EAA Type : '%s'", eaa.getEAAType()));
        }
    }

    private String getClaimedDocumentType() {
        switch (eaa.getEAAType()) {
            case SD_JWT_VC:
                return eaa.getVerifiableCredentialsTypeUri();
            case ISO_IEC_MDOC:
                // TODO : not clear what element is to be checked
                /*
                 * The attestation type for person identification data in ISO/IEC mdoc format
                 * shall be "eu.europa.ec.eudi.pid.1".
                 */
                return eaa.getAttestationDocumentType();
            default:
                throw new UnsupportedOperationException(String.format("Not supported EAA Type : '%s'", eaa.getEAAType()));
        }
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PID_DOCUMENT_TYPE;
    }

    @Override
    protected XmlMessage buildErrorMessage() {
        return buildXmlMessage(MessageTag.PID_DOCUMENT_TYPE_ANS, getClaimedDocumentType());
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