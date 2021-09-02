package eu.europa.esig.dss.pades.validation.scope;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfCMSRevision;
import eu.europa.esig.dss.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.scope.SignatureScope;

/**
 * An abstract class to find a PdfRevision scope
 *
 */
public abstract class PdfRevisionScopeFinder extends AbstractSignatureScopeFinder {

    /**
     * Finds signature scopes from a {@code PdfCMSRevision}
     *
     * @param pdfRevision {@link PdfCMSRevision}
     * @return {@link SignatureScope}
     */
    protected SignatureScope findSignatureScope(final PdfCMSRevision pdfRevision) {
        if (pdfRevision.areAllOriginalBytesCovered()) {
            return new FullPdfByteRangeSignatureScope(pdfRevision.getByteRange(), getOriginalPdfDigest(pdfRevision));
        } else {
            return new PartialPdfByteRangeSignatureScope(pdfRevision.getByteRange(), getOriginalPdfDigest(pdfRevision));
        }
    }

    private Digest getOriginalPdfDigest(final PdfCMSRevision pdfRevision) {
        DSSDocument originalDocument = PAdESUtils.getOriginalPDF(pdfRevision);
        return getDigest(originalDocument);
    }

}
