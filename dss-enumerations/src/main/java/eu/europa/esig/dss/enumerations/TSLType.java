package eu.europa.esig.dss.enumerations;

import java.util.Objects;

public interface TSLType {

    /**
     * Gets URI
     *
     * @return {@link String}
     */
    String getUri();

    /**
     * Gets label
     *
     * @return {@link String}
     */
    String getLabel();

    /**
     * This method returns a {@code TSLType} for the given URI
     *
     * @param uri {@link String}
     * @return {@link TSLTypeEnum}
     */
    static TSLType fromUri(String uri) {
        Objects.requireNonNull(uri, "URI cannot be null!");

        for (TSLType type : TSLTypeEnum.values()) {
            if (type.getUri().equals(uri)) {
                return type;
            }
        }
        return new TSLType() {
            @Override
            public String getUri() { return uri; }
            @Override
            public String getLabel() { return null; }
        };
    }

}
