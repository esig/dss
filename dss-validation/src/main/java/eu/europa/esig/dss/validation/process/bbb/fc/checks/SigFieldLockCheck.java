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
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;

/**
 * Verifies a signature according to given permissions for the signature field in /SigFieldLock
 *
 */
public class SigFieldLockCheck extends AbstractPdfLockDictionaryCheck {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param pdfRevision {@link SignatureWrapper}
     * @param constraint {@link PDFRevisionWrapper}
     */
    public SigFieldLockCheck(I18nProvider i18nProvider, XmlFC result, PDFRevisionWrapper pdfRevision, LevelRule constraint) {
        super(i18nProvider, result, pdfRevision, pdfRevision.getSigFieldLock(), constraint);
    }

    @Override
    protected boolean process() {
        if (!super.process()) {
            return false;
        }
        if (!pdfRevision.arePdfObjectModificationsDetected()) {
            return true;
        }
        if (pdfLockDictionary == null) {
            return true;
        }

        // optional
        if (pdfLockDictionary.getPermissions() != null) {
            switch (pdfLockDictionary.getPermissions()) {
                case NO_CHANGE_PERMITTED:
                    if (Utils.isCollectionNotEmpty(pdfRevision.getPdfSignatureOrFormFillChanges()) ||
                            Utils.isCollectionNotEmpty(pdfRevision.getPdfAnnotationChanges()) ||
                            Utils.isCollectionNotEmpty(pdfRevision.getPdfUndefinedChanges())) {
                        return false;
                    }
                    break;
                case MINIMAL_CHANGES_PERMITTED:
                    if (Utils.isCollectionNotEmpty(pdfRevision.getPdfAnnotationChanges()) ||
                            Utils.isCollectionNotEmpty(pdfRevision.getPdfUndefinedChanges())) {
                        return false;
                    }
                    break;
                case CHANGES_PERMITTED:
                    if (Utils.isCollectionNotEmpty(pdfRevision.getPdfUndefinedChanges())) {
                        return false;
                    }
                    break;
                default:
                    throw new UnsupportedOperationException(
                            String.format("The value '%s' is not supported!", pdfLockDictionary.getPermissions()));
            }
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_ISVASFLD;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_ISVASFLD_ANS;
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
