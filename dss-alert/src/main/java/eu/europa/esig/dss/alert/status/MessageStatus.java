package eu.europa.esig.dss.alert.status;

import java.util.Collection;

/**
 * Contains message describing the occurred event
 *
 */
public class MessageStatus implements Status {

    /** Message describing the occurred event */
    private String message;

    @Override
    public String getMessage() {
        return message;
    }

    /**
     * Sets the message describing the occurred event
     *
     * @param message {@link String}
     */
    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public Collection<String> getRelatedObjectIds() {
        throw new UnsupportedOperationException("getRelatedObjectIds() is not supported for the current implementation!");
    }

    @Override
    public boolean isEmpty() {
        return message == null || message.length() == 0;
    }

    @Override
    public String getErrorString() {
        return getMessage();
    }

    @Override
    public String toString() {
        return isEmpty() ? "Status : Valid" : getErrorString();
    }

}
