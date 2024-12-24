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
package eu.europa.esig.dss.pdfa.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFAInfo;
import eu.europa.esig.dss.pades.validation.PAdESDiagnosticDataBuilder;
import eu.europa.esig.dss.pdfa.PDFAValidationResult;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;

/**
 * This class is used to build a DiagnosticData for a PDF document validation,
 * including the validation result against the PDF/A specification
 *
 */
public class PAdESWithPDFADiagnosticDataBuilder extends PAdESDiagnosticDataBuilder {

    /** PDF/A validation result */
    private PDFAValidationResult pdfaValidationResult;

    /**
     * Default constructor
     */
    public PAdESWithPDFADiagnosticDataBuilder() {
        // empty
    }

    /**
     * Sets {@code PDFAValidationResult} and returns this builder
     *
     * @param pdfaValidationResult {@link PDFAValidationResult}
     * @return this {@link PAdESWithPDFADiagnosticDataBuilder}
     */
    public PAdESWithPDFADiagnosticDataBuilder pdfaValidationResult(PDFAValidationResult pdfaValidationResult) {
        this.pdfaValidationResult = pdfaValidationResult;
        return this;
    }

    @Override
    public XmlDiagnosticData build() {
        XmlDiagnosticData diagnosticData = super.build();
        diagnosticData.setPDFAInfo(getXmlPDFAInfo());
        return diagnosticData;
    }

    private XmlPDFAInfo getXmlPDFAInfo() {
        if (pdfaValidationResult != null) {
            XmlPDFAInfo xmlPDFAInfo = new XmlPDFAInfo();
            xmlPDFAInfo.setProfileId(pdfaValidationResult.getProfileId());
            xmlPDFAInfo.setCompliant(pdfaValidationResult.isCompliant());
            if (Utils.isCollectionNotEmpty(pdfaValidationResult.getErrorMessages())) {
                xmlPDFAInfo.setValidationMessages(new ArrayList<>(pdfaValidationResult.getErrorMessages()));
            }
            return xmlPDFAInfo;
        }
        return null;
    }

}
