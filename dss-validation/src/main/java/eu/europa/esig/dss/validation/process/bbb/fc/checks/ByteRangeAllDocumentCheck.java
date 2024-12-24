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
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class verifies if all signatures and document timestamps present in a PDF are valid
 *
 */
public class ByteRangeAllDocumentCheck extends ChainItem<XmlFC> {

    /** The diagnostic data */
    private final DiagnosticData diagnosticData;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param diagnosticData {@link DiagnosticData}
     * @param constraint {@link LevelConstraint}
     */
    public ByteRangeAllDocumentCheck(I18nProvider i18nProvider, XmlFC result, DiagnosticData diagnosticData,
                                     LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.diagnosticData = diagnosticData;
    }

    @Override
    protected boolean process() {
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (signature.getPDFRevision() != null && !signature.isSignatureByteRangeValid()) {
                return false;
            }
        }
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            if (timestamp.getPDFRevision() != null && !timestamp.isSignatureByteRangeValid()) {
                return false;
            }
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_DASTHVBR;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_DASTHVBR_ANS;
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
