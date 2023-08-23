package eu.europa.esig.dss.pki.factory;

import eu.europa.esig.dss.pki.db.JaxbCertEntityRepository;
import eu.europa.esig.dss.pki.service.*;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * A generic factory implementation that provides instances of various classes using a registration mechanism.
 * It allows registering factories for different classes and creates instances of those classes based on the registrations.
 */
public class GenericFactory implements Factory {
    // The map that holds the class-factory registrations.
    private Map<Class<?>, Supplier<?>> factoryMap = new HashMap<>();

    // The singleton instance of the GenericFactory.
    private static GenericFactory instance = null;

    /**
     * Registers a factory for a specific class.
     *
     * @param clazz   The class for which the factory is being registered.
     * @param factory A Supplier that provides an instance of the specified class.
     * @param <T>     The type of class for which the factory is being registered.
     */
    public <T> void registerFactory(Class<T> clazz, Supplier<T> factory) {
        factoryMap.put(clazz, factory);
    }

    /**
     * Private constructor to initialize the factory and perform default registrations.
     * This constructor is called only once when the getInstance() method is invoked for the first time.
     */
    private GenericFactory() {
        init();
    }

    /**
     * Get the singleton instance of the GenericFactory.
     *
     * @return The singleton instance of the GenericFactory.
     */
    public static GenericFactory getInstance() {
        if (instance == null) {
            synchronized (GenericFactory.class) {
                instance = new GenericFactory();
            }
        }
        return instance;
    }

    /**
     * Creates an instance of the specified class using the registered factory.
     * If no factory is found for the given class, an IllegalArgumentException is thrown.
     *
     * @param clazz The class for which an instance is to be created.
     * @param <T>   The type of class for which an instance is to be created.
     * @return An instance of the specified class.
     * @throws IllegalArgumentException If no factory is registered for the given class.
     */
    @Override
    public <T> T create(Class<T> clazz) {
        Supplier<?> factory = factoryMap.get(clazz);
        if (factory != null) {
            return (T) factory.get();
        }
        throw new IllegalArgumentException("Unknown class: " + clazz.getName());
    }

    /**
     * Initializes the factory with some default registrations.
     * This method is called from the constructor to provide default behavior for the factory.
     */
    private void init() {
        if (factoryMap.isEmpty()) {
            // Default registrations for some predefined classes.
            registerFactory(CertificateEntityService.class, CertificateEntityService::getInstance);
            registerFactory(TimestampGenerator.class, TimestampGenerator::getInstance);
//            registerFactory(LoaderXMlCertificate.class, LoaderXMlCertificate::getInstance);
            registerFactory(JaxbCertEntityRepository.class, JaxbCertEntityRepository::getInstance);
        }
    }
}

