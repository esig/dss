package eu.europa.esig.dss.enumerations;

/**
 * Defines possible levels for messages returned by the validation process
 *
 */
public enum MessageType implements UriBasedEnum {

    /**
     * The message indicates a reason for validation process failure
     */
    ERROR("urn:cef:dss:message:error"),

    /**
     * The message indicates a reason for an issue occurred during the validation, not blocking the process
     */
    WARN("urn:cef:dss:message:warning"),

    /**
     * The additional informational message returned by the validation process
     */
    INFO("urn:cef:dss:message:information");

    /** VR URI of the constraint */
    private final String uri;

    /**
     * Default constructor
     *
     * @param uri {@link String}
     */
    MessageType(String uri) {
        this.uri = uri;
    }

    @Override
    public String getUri() {
        return uri;
    }

}
