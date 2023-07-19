package eu.europa.esig.dss.pki.factory;

import eu.europa.esig.dss.pki.service.*;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class GenericFactory implements Factory<CertificateEntityService> {
    private Map<Class<?>, Supplier<?>> factoryMap = new HashMap<>();
    private static GenericFactory instance = null;

    public <T> void registerFactory(Class<T> clazz, Supplier<T> factory) {
        factoryMap.put(clazz, factory);
    }

    private GenericFactory() {
        init();
    }

    public static GenericFactory getInstance() {
        if (instance == null) {
            synchronized (GenericFactory.class) {
                instance = new GenericFactory();
            }
        }
        return instance;
    }


    @Override
    public <T> T create(Class<T> clazz) {
        Supplier<?> factory = factoryMap.get(clazz);
        if (factory != null) {
            return (T) factory.get();
        }

        throw new IllegalArgumentException("Unknown class: " + clazz.getName());


    }

    private void init() {
        if (factoryMap.isEmpty()) {
            registerFactory(CertificateEntityService.class, CertificateEntityService::getInstance);
            registerFactory(CRLGenerator.class, CRLGenerator::getInstance);
            registerFactory(Initializr.class, Initializr::getInstance);
            registerFactory(OCSPGenerator.class, OCSPGenerator::getInstance);
            registerFactory(KeystoreGenerator.class, KeystoreGenerator::getInstance);
            registerFactory(TimestampGenerator.class, TimestampGenerator::getInstance);
        }
    }
}
