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

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * This check verifies whether the certificate path depth of the current certificate is conformant
 * with BasicConstraints.pathLenConstraint value defined within intermediate CA certificates precessing in the chain
 *
 */
public class BasicConstraintsMaxPathLengthCheck extends ChainItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public BasicConstraintsMaxPathLengthCheck(I18nProvider i18nProvider, XmlSubXCV result,
                                              CertificateWrapper certificate, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        List<CertificateWrapper> certificateChain = certificate.getCertificateChain();
        /*
         * (k) max_path_length: this integer is initialized to n, is
         * decremented for each non-self-issued certificate in the path,
         * and may be reduced to the value in the path length constraint
         * field within the basic constraints extension of a CA
         * certificate.
         */
        int maxPathLength = certificateChain.size() + 1; // certificate chain does not return current certificate
        for (int i = certificateChain.size() - 1; i > -1; i--) {
            /*
             * (l) If the certificate was not self-issued, verify that
             * max_path_length is greater than zero and decrement
             * max_path_length by 1.
             */
            CertificateWrapper cert = certificateChain.get(i);
            if (!cert.isSelfSigned()) {
                --maxPathLength;
            }
            int pathLenConstraint = cert.getPathLenConstraint();
            /*
             * (m) If pathLenConstraint is present in the certificate and is
             * less than max_path_length, set max_path_length to the value
             * of pathLenConstraint.
             */
            if (pathLenConstraint != -1 && pathLenConstraint < maxPathLength) {
                maxPathLength = pathLenConstraint;
            }
        }
        return maxPathLength > 0;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_ICPDV;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_ICPDV_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE;
    }

}