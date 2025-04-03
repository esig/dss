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
import eu.europa.esig.dss.diagnostic.QCLimitValueWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.NumericValueRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks the minimal allowed QC transaction limit for the certificate
 */
public class CertificateMinQcTransactionLimitCheck extends ChainItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /** The constraint from policy file */
    private final NumericValueRule constraint;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link NumericValueRule}
     */
    public CertificateMinQcTransactionLimitCheck(I18nProvider i18nProvider, XmlSubXCV result,
                                                 CertificateWrapper certificate, NumericValueRule constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.constraint = constraint;
    }

    @Override
    protected boolean process() {
        QCLimitValueWrapper qcLimitValue = certificate.getQCLimitValue();
        if (qcLimitValue != null) {
            /*
             * EN 319 412-5 (ch. 4.3.2 QCStatement regarding limits on the value of transactions) :
             *
             * -- value = amount * 10^exponent
             */
            double value = qcLimitValue.getAmount() * Math.pow(10, qcLimitValue.getExponent());
            return value >= constraint.getValue().intValue();
        }
        // not present
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCLVA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCLVA_ANS;
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
