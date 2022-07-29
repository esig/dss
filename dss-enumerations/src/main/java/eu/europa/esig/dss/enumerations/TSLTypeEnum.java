package eu.europa.esig.dss.enumerations;

/**
 * Defines common TSLType values supported by the implementation
 *
 */
public enum TSLTypeEnum implements TSLType {

    /** EU List of the Trusted Lists */
    EUlistofthelists("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists", "EU List of the Trusted Lists"),

    /** EU Trusted Lists */
    EUgeneric("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", "EU Trusted List"),

    /** AdES List of the Trusted Lists */
    AdESlistofthelists("http://ec.europa.eu/tools/lotl/mra/ades-lotl-tsl-type", "AdES List of the Trusted Lists");

    /** URI associated with the TSPType */
    private String uri;

    /** Name of the TSLType */
    private String label;

    /**
     * Default constructor
     *
     * @param uri {@link String}
     * @param label {@link String}
     */
    TSLTypeEnum(final String uri, final String label) {
        this.uri = uri;
        this.label = label;
    }

    @Override
    public String getUri() {
        return uri;
    }

    @Override
    public String getLabel() {
        return label;
    }

}
