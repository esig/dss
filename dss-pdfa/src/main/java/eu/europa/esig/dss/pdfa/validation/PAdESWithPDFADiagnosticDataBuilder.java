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
