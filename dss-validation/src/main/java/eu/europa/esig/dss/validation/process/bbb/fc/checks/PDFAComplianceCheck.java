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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class checks whether the input document is a compliant according to the determined PDF/A format
 */
public class PDFAComplianceCheck extends ChainItem<XmlFC> {

    /** Defines whether the document is compliant to PDF/A */
    private final boolean pdfaCompliant;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param pdfaCompliant defines whether the document is PDF/A compliant
     * @param constraint {@link LevelConstraint}
     */
    public PDFAComplianceCheck(I18nProvider i18nProvider, XmlFC result, boolean pdfaCompliant, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.pdfaCompliant = pdfaCompliant;
    }

    @Override
    protected boolean process() {
        return pdfaCompliant;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_IDPDFAC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_IDPDFAC_ANS;
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
