package eu.europa.esig.dss.spi.tsl;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Defines a TSLType element of a Trusted List
 *
 */
public class TSLType {

    /** Map of registered TSLTypes */
    private static Map<String, TSLType> tslTypes = new HashMap<>();

    /** EU List of the Trusted Lists */
    public static final TSLType EUlistofthelists = new TSLType(
            "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists", "EU List of the Trusted Lists");

    /** EU Trusted Lists */
    public static final TSLType EUgeneric = new TSLType(
            "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", "EU Trusted List");

    /** AdES List of the Trusted Lists */
    public static final TSLType AdESlistofthelists = new TSLType(
            "https://ec.europa.eu/tools/lotl/recognition/TrstSvc/TrustedList/TSLType/AdESlistofthelists", "AdES List of the Trusted Lists");

    /** URI associated with the TSPType */
    private final String uri;

    /** Name of the TSLType */
    private final String label;

    /**
     * Constructor with URI only
     *
     * @param uri {@link String}
     */
    private TSLType(final String uri) {
        this(uri, null);
    }

    /**
     * Default constructor
     *
     * @param uri {@link String}
     * @param label {@link String}
     */
    private TSLType(final String uri, final String label) {
        this.uri = uri;
        this.label = label;
        tslTypes.put(uri, this);
    }

    /**
     * Gets URI
     *
     * @return {@link String}
     */
    public String getUri() {
        return uri;
    }

    /**
     * Gets label
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * This method returns a {@code TSLType} for the given URI
     *
     * @param uri {@link String}
     * @return {@link TSLType}
     */
    public static TSLType fromUri(String uri) {
        Objects.requireNonNull(uri, "URI cannot be null!");

        TSLType tslType = tslTypes.get(uri);
        if (tslType == null) {
            tslType = new TSLType(uri);
        }
        return tslType;
    }

}
