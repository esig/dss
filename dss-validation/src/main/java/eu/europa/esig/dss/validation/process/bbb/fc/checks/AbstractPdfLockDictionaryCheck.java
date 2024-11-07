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
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * An abstract class for PDF lock dictionary validation
 *
 */
public abstract class AbstractPdfLockDictionaryCheck extends ChainItem<XmlFC> {

    /** The PDF revision */
    protected final PDFRevisionWrapper pdfRevision;

    /** Corresponding lock dictionary */
    protected final XmlPDFLockDictionary pdfLockDictionary;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param pdfRevision {@link PDFRevisionWrapper}
     * @param pdfLockDictionary {@link XmlPDFLockDictionary}
     * @param constraint {@link LevelConstraint}
     */
    protected AbstractPdfLockDictionaryCheck(I18nProvider i18nProvider, XmlFC result, PDFRevisionWrapper pdfRevision,
                                             XmlPDFLockDictionary pdfLockDictionary, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.pdfRevision = pdfRevision;
        this.pdfLockDictionary = pdfLockDictionary;
    }

    @Override
    protected boolean process() {
        if (!pdfRevision.arePdfObjectModificationsDetected()) {
            return true;
        }
        if (pdfLockDictionary == null) {
            return true;
        }

        List<String> modifiedFieldNames = pdfRevision.getModifiedFieldNames();
        if (Utils.isCollectionEmpty(modifiedFieldNames)) {
            return true;
        }

        List<String> lockedFields = pdfLockDictionary.getFields();
        if (pdfLockDictionary.getAction() != null) {
            switch (pdfLockDictionary.getAction()) {
                case ALL:
                    return false;

                case EXCLUDE:
                    for (String fieldName : modifiedFieldNames) {
                        if (!lockedFields.contains(fieldName)) {
                            return false;
                        }
                    }
                    return true;

                case INCLUDE:
                    for (String fieldName : modifiedFieldNames) {
                        if (lockedFields.contains(fieldName)) {
                            return false;
                        }
                    }
                    return true;

                default:
                    throw new UnsupportedOperationException(
                            String.format("The value '%s' is not supported!", pdfLockDictionary.getAction()));
            }
        }
        return true;
    }

}
