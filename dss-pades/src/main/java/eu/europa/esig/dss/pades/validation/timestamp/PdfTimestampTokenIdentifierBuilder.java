package eu.europa.esig.dss.pades.validation.timestamp;

import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.spi.x509.tsp.TimestampIdentifierBuilder;

/**
 * Builds an {@code eu.europa.esig.dss.spi.x509.tsp.TimestampTokenIdentifier}
 * for a {@code eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken}
 *
 */
public class PdfTimestampTokenIdentifierBuilder extends TimestampIdentifierBuilder {

    private static final long serialVersionUID = -6655656136412456482L;

    /**
     * PDF document time-stamp token
     */
    private final PdfTimestampToken pdfTimestampToken;

    /**
     * Default constructor to build an identifier for a {@code PdfTimestampToken}
     *
     * @param pdfTimestampToken {@link PdfTimestampToken}
     */
    public PdfTimestampTokenIdentifierBuilder(final PdfTimestampToken pdfTimestampToken) {
        super(pdfTimestampToken.getEncoded());
        this.pdfTimestampToken = pdfTimestampToken;
    }

    @Override
    protected String getTimestampPosition() {
        StringBuilder stringBuilder = new StringBuilder();
        PdfDocTimestampRevision pdfRevision = pdfTimestampToken.getPdfRevision();
        for (PdfSignatureField signatureField : pdfRevision.getFields()) {
            stringBuilder.append(signatureField.getFieldName());
        }
        return stringBuilder.toString();
    }

}
