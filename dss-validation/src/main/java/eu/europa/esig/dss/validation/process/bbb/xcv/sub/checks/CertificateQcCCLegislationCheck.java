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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

/**
 * Checks if the country code or set of country codes defined in QcCCLegislation is supported by the policy
 */
public class CertificateQcCCLegislationCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /** The constraint */
    private final MultiValuesConstraint constraint;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link MultiValuesConstraint}
     */
    public CertificateQcCCLegislationCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                                     MultiValuesConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.constraint = constraint;
    }

    @Override
    protected boolean process() {
        return processValuesCheck(certificate.getQcLegislationCountryCodes());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_CMDCDCQCCLCEC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        if (Utils.isCollectionEmpty(constraint.getId())) {
            /**
             * See EN 319 412-5 ch. 4.2.1
             *
             * A certificate that includes the esi4-qcStatement-1 statement with the aim to declare that it is
             * an EU qualified certificate that is issued according to Directive 1999/93/EC [i.3] or
             * the Annex I, III or IV of the Regulation (EU) No 910/2014 [i.8] whichever is in force
             * at the time of issuance:
             *
             * a) shall not include the QcCClegislation statement;
             * ...
             */
            return MessageTag.BBB_XCV_CMDCDCQCCLCEC_ANS_EU;
        }
        return MessageTag.BBB_XCV_CMDCDCQCCLCEC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
    }

}
