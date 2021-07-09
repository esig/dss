package eu.europa.esig.dss.model.x509;

/**
 * PdsLocation::= SEQUENCE {
 *  url IA5String,
 *  language PrintableString (SIZE(2))} --ISO 639-1 language code
 */
public class PdsLocation {

    /** The URL */
    private String url;

    /** The language */
    private String language;

    /**
     * Returns URL
     *
     * @return {@link String}
     */
    public String getUrl() {
        return url;
    }

    /**
     * Sets URL
     *
     * @param url {@link String}
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Returns the language
     *
     * @return {@link String}
     */
    public String getLanguage() {
        return language;
    }

    /**
     * Sets language
     *
     * @param language {@link String}
     */
    public void setLanguage(String language) {
        this.language = language;
    }

}
