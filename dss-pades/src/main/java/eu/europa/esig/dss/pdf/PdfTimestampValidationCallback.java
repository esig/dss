package eu.europa.esig.dss.pdf;

/**
 * Use this callback to be called only for Timestamps, not for Signatures
 *
 */
public abstract class PdfTimestampValidationCallback implements SignatureValidationCallback {

    @Override
    public void validate(PdfSignatureOrDocTimestampInfo pdfSignatureOrDocTimestampInfo) {
        if (pdfSignatureOrDocTimestampInfo instanceof PdfDocTimestampInfo) {
        	PdfDocTimestampInfo docTimestampInfo = (PdfDocTimestampInfo) pdfSignatureOrDocTimestampInfo;
            validate(docTimestampInfo);
        }

    }

    public abstract void validate(PdfDocTimestampInfo docTimestampInfo);

}
