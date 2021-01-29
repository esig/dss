package eu.europa.esig.dss.jaxb.common;

import java.util.Objects;

/**
 * Represents the Message returned in the validation process
 */
public class Message {

    /** Represents the message key */
    private final String key;

    /** Represents the message text value */
    private final String value;

    /**
     * Default constructor
     *
     * @param key {@link String}
     * @param value {@link String}
     */
    public Message(final String key, final String value) {
        this.key = key;
        this.value = value;
    }

    /**
     * Gets the message key.
     *
     * @return {@link String}
     *
     */
    public String getKey() {
        return key;
    };

    /**
     * Gets the value of the message.
     *
     * @return {@link String}
     */
    public String getValue() {
        return value;
    };

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Message message = (Message) o;

        if (!Objects.equals(key, message.key)) return false;
        return Objects.equals(value, message.value);
    }

    @Override
    public int hashCode() {
        int result = key != null ? key.hashCode() : 0;
        result = 31 * result + (value != null ? value.hashCode() : 0);
        return result;
    }

}
