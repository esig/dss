package eu.europa.esig.dss.pdf;

/**
 * Use this callback to be called only for Timestamps, not for Signatures
 *
 */
public abstract class PdfTimestampValidationCallback implements SignatureValidationCallback {

    @Override
    public void validate(PdfRevision pdfRevision) {
        if (pdfRevision instanceof PdfDocTimestampRevision) {
        	PdfDocTimestampRevision docTimestampRevision = (PdfDocTimestampRevision) pdfRevision;
            validate(docTimestampRevision);
        }

    }

    public abstract void validate(PdfDocTimestampRevision pdfDocTimestampRevision);

}
