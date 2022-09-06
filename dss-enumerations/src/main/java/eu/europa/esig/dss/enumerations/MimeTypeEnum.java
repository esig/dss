package eu.europa.esig.dss.enumerations;

/**
 * Contains default MimeType enumerations
 *
 */
public enum MimeTypeEnum implements MimeType {

    /** octet-stream */
    BINARY("application/octet-stream"),

    /** plain text */
    TEXT("text/plain", "txt"),

    /** xml */
    XML("text/xml", "xml"),

    /** html */
    HTML("text/html", "html"),

    /** pdf */
    PDF ("application/pdf", "pdf"),

    /** json */
    JSON("application/json", "json"),

    /** jose */
    JOSE("application/jose", "jose"),

    /** jose+json */
    JOSE_JSON("application/jose+json", "json"),

    /** pkcs7-signature */
    PKCS7("application/pkcs7-signature", "pkcs7", "p7m", "p7s"),

    /** timestamp-token */
    TST("application/vnd.etsi.timestamp-token", "tst"),

    /** crl */
    CRL("application/pkix-crl", "crl"),

    /** certificate */
    CER("application/pkix-cert", "cer", "crt"),

    /** zip */
    ZIP("application/zip", "zip"),

    /** asic-s */
    ASICS("application/vnd.etsi.asic-s+zip", "scs", "asics"),

    /** asic-e */
    ASICE("application/vnd.etsi.asic-e+zip", "sce", "asice", "bdoc"),

    /** opendocument text */
    ODT("application/vnd.oasis.opendocument.text", "odt"),

    /** opendocument spreadsheet */
    ODS("application/vnd.oasis.opendocument.spreadsheet", "ods"),

    /** opendocument presentation */
    ODP("application/vnd.oasis.opendocument.presentation", "odp"),

    /** opendocument graphics */
    ODG("application/vnd.oasis.opendocument.graphics", "odg"),

    /** png */
    PNG("image/png", "png"),

    /** jpeg */
    JPEG("image/jpeg", "jpg", "jpeg"),

    /** svg */
    SVG("image/svg+xml", "svg");

    /** MimeType identifier */
    final String mimeTypeString;

    /** File extension corresponding to the MimeType */
    final String[] extensions;

    /**
     * Default constructor
     *
     * @param mimeTypeString {@link String} MimeType identifier
     * @param extensions array of {@link String} file extensions
     */
    MimeTypeEnum(final String mimeTypeString, final String... extensions) {
        this.extensions = extensions;
        this.mimeTypeString = mimeTypeString;
    }

    @Override
    public String getMimeTypeString() {
        return mimeTypeString;
    }

    @Override
    public String getExtension() {
        if (extensions != null && extensions.length > 0) {
            return extensions[0];
        }
        return null;
    }

}
