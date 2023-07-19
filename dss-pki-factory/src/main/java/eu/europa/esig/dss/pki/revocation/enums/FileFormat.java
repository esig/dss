package eu.europa.esig.dss.pki.revocation.enums;

import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.revocation.PkiDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;

import java.util.Arrays;
import java.util.function.BiFunction;

public enum FileFormat {

    CERTIFICATE(PkiDataLoader::certificationGet, "pki-factory/crt/"),
    KEYSTORE(PkiDataLoader::keyStoreGet, "pki-factory/keystore/"),
    TIMESTAMP((pkiDataLoader, url, content) -> pkiDataLoader.tsaPost(url, content).getData(), "pki-factory/tsa/"),
    OCSP((pkiDataLoader, url, content) -> pkiDataLoader.ocspPost(url, content).getData(), "pki-factory/ocsp/"),
    CRL(PkiDataLoader::crlGet, "pki-factory/crl/");


    private final String type;
    private BiFunction<PkiDataLoader, String, DataLoader.DataAndUrl> function;
    private TriFunction<PkiDataLoader, String, byte[], byte[]> triFunction;


    FileFormat(TriFunction<PkiDataLoader, String, byte[], byte[]> function, final String type) {
        this.triFunction = function;
        this.type = type;

    }

    FileFormat(BiFunction<PkiDataLoader, String, DataLoader.DataAndUrl> function, final String type) {
        this.function = function;
        this.type = type;
    }


    public static FileFormat getType(final String type) {
        return Arrays.stream(FileFormat.values())
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
