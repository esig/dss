package eu.europa.esig.dss.pki.factory;

public interface Factory<T> {
    <T> T create(Class<T> responseClass);
}

