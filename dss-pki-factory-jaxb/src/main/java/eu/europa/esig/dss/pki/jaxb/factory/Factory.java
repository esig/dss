package eu.europa.esig.dss.pki.jaxb.factory;

/**
 * The Factory interface represents a generic factory for creating instances of objects.
 * Implementations of this interface provide a way to create instances of various classes.
 */
public interface Factory {

    /**
     * Creates an instance of the specified class.
     *
     * @param responseClass The Class representing the type of object to be created.
     * @return An instance of the specified class.
     */
    <T> T create(Class<T> responseClass);
}

