package eu.europa.esig.dss.model.x509;

/**
 * PdsLocation::= SEQUENCE {
 *  url IA5String,
 *  language PrintableString (SIZE(2))} --ISO 639-1 language code
 */
public class PdsLocation {

    private String url;
    private String language;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

}
