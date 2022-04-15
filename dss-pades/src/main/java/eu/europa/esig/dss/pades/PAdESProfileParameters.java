package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.ProfileParameters;
import eu.europa.esig.dss.pdf.PdfSignatureCache;

/**
 * This class is used to accelerate signature creation process for PAdES.
 * The cache is set within {@code PAdESService.getDataToSign(...)} method and
 * used in {@code PAdESService.signDocument(...)} method.
 *
 */
public class PAdESProfileParameters extends ProfileParameters {

    private static final long serialVersionUID = 852030281057208148L;

    /**
     * Internal cache used to accelerate the signature creation process
     */
    private PdfSignatureCache pdfToBeSignedCache;

    /**
     * Gets the PDF signature cache
     *
     * @return {@link PdfSignatureCache}
     */
    public PdfSignatureCache getPdfToBeSignedCache() {
        if (pdfToBeSignedCache == null) {
            pdfToBeSignedCache = new PdfSignatureCache();
        }
        return pdfToBeSignedCache;
    }

    /**
     * Sets the PDF signature cache
     *
     * @param pdfToBeSignedCache {@link PdfSignatureCache}
     */
    public void setPdfToBeSignedCache(PdfSignatureCache pdfToBeSignedCache) {
        this.pdfToBeSignedCache = pdfToBeSignedCache;
    }

}
