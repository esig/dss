package eu.europa.esig.dss.pki.x509.revocation.enums;

import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.x509.revocation.PkiDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;

import java.util.Arrays;
import java.util.function.BiFunction;


public enum PkiDataLoaderType {

    CERTIFICATE(PkiDataLoader::certificationGet, "pki-factory/crt/"),
    KEYSTORE(PkiDataLoader::keyStoreGet, "pki-factory/keystore/"),
    TIMESTAMP((pkiDataLoader, url, content) -> pkiDataLoader.tsaPost(url, content).getData(), "pki-factory/tsa/"),
    OCSP((pkiDataLoader, url, content) -> pkiDataLoader.ocspPost(url, content).getData(), "pki-factory/ocsp/"),
    CRL(PkiDataLoader::crlGet, "pki-factory/crl/");


    private final String type;
    private BiFunction<PkiDataLoader, String, DataLoader.DataAndUrl> function;
    private TriFunction<PkiDataLoader, String, byte[], byte[]> triFunction;


    /**
     * Constructs a FileFormat enum with a TriFunction for data loading and the associated file format type.
     *
     * @param function The TriFunction for data loading.
     * @param type The associated file format type.
     */
    PkiDataLoaderType(TriFunction<PkiDataLoader, String, byte[], byte[]> function, final String type) {
        this.triFunction = function;
        this.type = type;

    }


    /**
     * Constructs a FileFormat enum with a BiFunction for data loading and the associated file format type.
     *
     * @param function The BiFunction for data loading.
     * @param type The associated file format type.
     */
    PkiDataLoaderType(BiFunction<PkiDataLoader, String, DataLoader.DataAndUrl> function, final String type) {
        this.function = function;
        this.type = type;
    }

    /**
     * Retrieves the FileFormat enum based on the given file format type.
     *
     * @param type The file format type to match with the FileFormat enum.
     * @return The corresponding FileFormat enum.
     * @throws Error500Exception if no matching FileFormat enum is found.
     */
    public static PkiDataLoaderType getType(final String type) {
        return Arrays.stream(PkiDataLoaderType.values())
                .filter(fileType -> type.contains(fileType.type))
                .findFirst()
                .orElseThrow(() -> new Error500Exception("Bad url"));
    }


    public BiFunction<PkiDataLoader, String, DataLoader.DataAndUrl> getFunction() {
        return function;
    }

    public TriFunction<PkiDataLoader, String, byte[], byte[]> getTriFunction() {
        return triFunction;
    }
}
