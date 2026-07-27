/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.lote.sync.LoTEExpirationAndSignatureCheckStrategy;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.job.DownloadInfoRecord;
import eu.europa.esig.dss.model.job.ParsingInfoRecord;
import eu.europa.esig.dss.model.job.ValidationInfoRecord;
import eu.europa.esig.dss.model.lote.LoLoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.validation.job.cache.CacheCleaner;
import eu.europa.esig.dss.validation.job.sync.AcceptAllStrategy;
import eu.europa.esig.dss.validation.job.sync.SynchronizationStrategy;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.Executors;

public class LoTEValidationJobSnippets {

    public void sample() throws IOException {

        // tag::multi-trusted-certificate-sources[]
        // import eu.europa.esig.dss.spi.validation.CertificateVerifier;
        // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setTrustedCertSources(trustStoreSource(), trustedListSource());
        // end::multi-trusted-certificate-sources[]
    }

    public CertificateSource trustStoreSource() throws IOException {
        // tag::trust-store[]
        // import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
        // import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
        // import eu.europa.esig.dss.spi.DSSUtils;

        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12", getPassword());

        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.importAsTrusted(keystore);

        // Optionally, certificates can also be directly added
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIC9TCCAd2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADArMQswCQYDVQQGEwJBQTEMMAoGA1UEChMDRFNTMQ4wDAYDVQQDEwVJQ0EgQTAeFw0xMzEyMDIxNzMzMTBaFw0xNTEyMDIxNzMzMTBaMDAxCzAJBgNVBAYTAkFBMQwwCgYDVQQKEwNEU1MxEzARBgNVBAMTCnVzZXIgQSBSU0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJUHHAphmSDdQ1t62tppK+dLTANsE2nAj+HCpasS3ohlBsrhteRsvTAbrDyIzCmTYWu/nVI4TGvbzBESwV/QitlkoMLpYFw32MIBf2DLmECzGJ3vm5haw6u8S9quR1h8Vu7QWd+5KMabZuR+j91RiSuoY0xS2ZQxJw1vhvW9hRYjAgMBAAGjgaIwgZ8wCQYDVR0TBAIwADAdBgNVHQ4EFgQU9ESnTWfwg13c3LQZzqqwibY5WVYwUwYDVR0jBEwwSoAUIO1CDsBSUcEoFZxKaWf1PAL1U+uhL6QtMCsxDDAKBgNVBAoTA0RTUzELMAkGA1UEBhMCQUExDjAMBgNVBAMTBVJDQSBBggEBMAsGA1UdDwQEAwIHgDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEFBQADggEBAGnhhnoyVUhDnr/BSbZ/uWfSuwzFPG+2V9K6WxdIaaXOORFGIdFwGlAwA/Qzpq9snfBxuTkAykxq0uEDhHTj0qXxWRjQ+Dop/DrmccoF/zDvgGusyY1YXaABd/kc3IYt7ns7z3tpiqIz4A7a/UHplBRXfqjyaZurZuJQRaSdxh6CNhdEUiUBxkbb1SdMjuOgjzSDjcDjcegjvDquMKdDetvtu2Qh4ConBBo3fUImwiFRWnbudS5H2HE18ikC7gY/QIuNr7USf1PNyUgcG2g31cMtemj7UTBHZ2V/jPf7ZXqwfnVSaYkNvM3weAI6R3PI0STjdxN6a9qjt9xld40YEdw="));
        // end::trust-store[]

        return trustedCertificateSource;
    }

    public CertificateSource trustedListSource() {
        // tag::trusted-entities-source[]
        // import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();
        // end::trusted-entities-source[]
        return trustedEntitiesCertificateSource;
    }

    private char[] getPassword() {
        return "dss-password".toCharArray();
    }

    public void jobConfig() {
        // tag::job-config-sources[]
        // import eu.europa.esig.dss.lote.job.LoTEValidationJob;

        LoTEValidationJob validationJob = new LoTEValidationJob();
        // Specify where the LoTE/LoLoTE is hosted and which are the signing certificate(s) for these LoTE/LoLoTE.
        validationJob.setLoTESources(pidProvidersListSource(), walletProvidersListSource());
        validationJob.setLoLoTESources(euLoLoTESource());
        // end::job-config-sources[]
    }

    public void refresh() {
        // tag::refresh[]
        // import eu.europa.esig.dss.lote.job.LoTEValidationJob;

        LoTEValidationJob validationJob = new LoTEValidationJob();

        // tag::offline-refresh[]
        // call with the Offline Loader (application initialization)
        validationJob.offlineRefresh();
        // end::offline-refresh[]

        // call with the Online Loader (callable every day/hour in a cron)
        validationJob.onlineRefresh();

        // end::refresh[]
    }

    // tag::job-loaders[]
    // import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader;
    // import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
    // import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;

    public DSSCacheFileLoader offlineLoader() {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(-1); // negative value means cache never expires
        offlineFileLoader.setDataLoader(new IgnoreDataLoader()); // do not download from Internet
        offlineFileLoader.setFileCacheDirectory(cacheDirectory());
        return offlineFileLoader;
    }

    public DSSCacheFileLoader onlineLoader() {
        FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(dataLoader()); // instance of DataLoader which can access to Internet (proxy,...)
        onlineFileLoader.setFileCacheDirectory(cacheDirectory());
        return onlineFileLoader;
    }
    // end::job-loaders[]

    public void synchronizationStrategyConfiguration() {
        // tag::synchronization-strategy[]
        // import eu.europa.esig.dss.lote.job.LoTEValidationJob;
        // import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
        // import eu.europa.esig.dss.validation.job.sync.AcceptAllStrategy;

        LoTEValidationJob LoTEValidationJob = new LoTEValidationJob();

        // AcceptAllStrategy will accept all Trusted Lists, despite its signature validation status (used by default)
        LoTEValidationJob.setSynchronizationStrategy(new AcceptAllStrategy<>());

        // ExpirationAndSignatureCheckStrategy allow configuring acceptance of various checks to be performed on Trusted Lists
        LoTEExpirationAndSignatureCheckStrategy checkStrategy = new LoTEExpirationAndSignatureCheckStrategy();
        // This check configures whether expired LoLoTEs shall be accepted, otherwise they will be skipped (FALSE by default)
        checkStrategy.setAcceptExpiredListOfLists(false);
        // This check configures whether expired LoTEs shall be accepted, otherwise they will be skipped (FALSE by default)
        checkStrategy.setAcceptExpiredList(false);
        // This check configures whether LoLoTEs with invalid signatures shall be accepted, otherwise they will be skipped (FALSE by default)
        checkStrategy.setAcceptInvalidListOfLists(false);
        // This check configures whether LoTEs with invalid signatures shall be accepted, otherwise they will be skipped (FALSE by default)
        checkStrategy.setAcceptInvalidList(false);
        // Provide the configured strategy to the LoTEValidationJob
        LoTEValidationJob.setSynchronizationStrategy(checkStrategy);
        // end::synchronization-strategy[]
    }

    public void allValidTrustedListsStrategy() {
        LoTEValidationJob LoTEValidationJob = new LoTEValidationJob();

        // tag::custom-strategy[]
        // import eu.europa.esig.dss.validation.job.sync.SynchronizationStrategy;
        // import eu.europa.esig.dss.model.lote.LoTEInfo;
        // import eu.europa.esig.dss.model.lote.LoLoTEInfo;

        // Create a custom strategy by implementing the interface
        // This strategy will accept only LoLoTE/TLs with valid signatures
        SynchronizationStrategy<LoTEInfo, LoLoTEInfo> customStrategy = new SynchronizationStrategy<LoTEInfo, LoLoTEInfo>() {

            @Override
            public boolean canBeSynchronized(LoTEInfo lote) {
                return lote.getValidationCacheInfo().isValid();
            }

            @Override
            public boolean canBeSynchronized(LoLoTEInfo lolote) {
                return lolote.getValidationCacheInfo().isValid();
            }

        };

        // Provide the strategy to the LoTEValidationJob
        LoTEValidationJob.setSynchronizationStrategy(customStrategy);
        // end::custom-strategy[]

    }

    public CacheCleaner cacheCleaner() {
        // tag::cache-cleaner[]
        // import eu.europa.esig.dss.validation.job.cache.CacheCleaner;

        // Create CacheCleaner
        CacheCleaner cacheCleaner = new CacheCleaner();
        // free the space in memory
        cacheCleaner.setCleanMemory(true);
        // remove the stored file(s) on the file-system
        cacheCleaner.setCleanFileSystem(true);
        // if the file-system cleaner is enabled, inject the configured loader from the
        // online or offline refresh data loader.
        cacheCleaner.setDSSFileLoader(offlineLoader());
        // end::cache-cleaner[]

        return cacheCleaner;
    }

    private void executorService() {
        // tag::executor-service[]
        // import eu.europa.esig.dss.lote.job.LoTEValidationJob;
        // import java.util.concurrent.Executors;

        LoTEValidationJob LoTEValidationJob = new LoTEValidationJob();
        // Allows configuration of the execution process
        // Default : Executors.newCachedThreadPool() is used
        LoTEValidationJob.setExecutorService(Executors.newSingleThreadExecutor());
        // end::executor-service[]
    }

    private DataLoader dataLoader() {
        return new CommonsDataLoader();
    }

    private File cacheDirectory() {
        return null;
    }

    public void summary() {
        // tag::lote-summary[]
        // import eu.europa.esig.dss.model.job.DownloadInfoRecord;
        // import eu.europa.esig.dss.model.job.ParsingInfoRecord;
        // import eu.europa.esig.dss.model.job.ValidationInfoRecord;
        // import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
        // import eu.europa.esig.dss.lote.job.LoTEValidationJob;
        // import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
        // import eu.europa.esig.dss.model.lote.LoLoTEInfo;
        // import eu.europa.esig.dss.model.lote.LoTEInfo;
        // import java.util.List;

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();

        LoTEValidationJob job = new LoTEValidationJob();
        job.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);

        // ... config & refresh ...

        // A cache content summary can be computed on request
        LoTEValidationJobSummary summary = job.getSummary();

        // All information about processed LoLoTESources
        List<LoLoTEInfo> LoLoTEInfos = summary.getLoLoTEInfos();
        LoLoTEInfo LoLoTEInfo = LoLoTEInfos.get(0);
        // All data about the download (last occurrence, cache status, error,...)
        DownloadInfoRecord downloadCacheInfo = LoLoTEInfo.getDownloadCacheInfo();

        // All data about the parsing (date, extracted data, cache status,...)
        ParsingInfoRecord parsingCacheInfo = LoLoTEInfo.getParsingCacheInfo();

        // All data about the signature validation (signing certificate, validation
        // result, cache status,...)
        ValidationInfoRecord validationCacheInfo = LoLoTEInfo.getValidationCacheInfo();

        // All information about processed LoTESources (which are not linked to a
        // LoLoTESource)
        List<LoTEInfo> otherLoTEInfos = summary.getOtherLoTEInfos();

        // or the last update can be collected from the TrustedEntitiesCertificateSource
        LoTEValidationJobSummary lastSynchronizedSummary = trustedEntitiesCertificateSource.getSummary();

        // end::lote-summary[]

        downloadCacheInfo.getLastStateTransitionTime();
        parsingCacheInfo.getLastStateTransitionTime();
        validationCacheInfo.getLastStateTransitionTime();
        lastSynchronizedSummary.getLoLoTEInfos();
    }

    private LoTESource walletProvidersListSource() {
        return null;
    }

    private LoTESource pidProvidersListSource() {
        // tag::pid-list-source[]
        // import eu.europa.esig.dss.lote.job.LoTEValidationJob;
        // import eu.europa.esig.dss.lote.source.LoTESource;
        // import eu.europa.esig.dss.tsl.function.GrantedTrustService;

        LoTEValidationJob LoTEValidationJob = new LoTEValidationJob();
        LoTESource loteSource = new LoTESource();

        // Mandatory : The url where the LoTE needs to be downloaded
        loteSource.setUrl("https://eidas.ec.europa.eu/efda/wallet/lists-of-trusted-entities/pid-providers");

        // A certificate source which contains the signing certificate(s) for the
        // current trusted list
        loteSource.setCertificateSource(getSigningCertificatesForPIDProvidersList());

        // Optional : configure predicates
        // Default : none (select all)

        // ... omitted ...

        //instance of CertificateSource where all trusted certificates and their properties (service type,...) are stored.
        LoTEValidationJob.setLoTESources(loteSource);
        // end::pid-list-source[]

        return loteSource;
    }

    public LoLoTESource euLoLoTESource() {
        // tag::european-LoLoTE-source[]
        // import eu.europa.esig.dss.lote.job.LoTEValidationJob;
        // import eu.europa.esig.dss.tsl.source.LoLoTESource;
        // import eu.europa.esig.dss.tsl.function.EULoLoTEOtherTSLPointer;
        // import eu.europa.esig.dss.tsl.function.EUTLOtherTSLPointer;
        // import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
        // import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
        // import eu.europa.esig.dss.tsl.function.GrantedTrustService;

        LoTEValidationJob LoTEValidationJob = new LoTEValidationJob();
        // tag::european-LoLoTE-keystore[]
        LoLoTESource loloteSource = new LoLoTESource();
        // end::european-LoLoTE-keystore[]

        // Mandatory : The url where the LoLoTE needs to be downloaded
        loloteSource.setUrl("https://ec.europa.eu/tools/LoLoTE/eu-LoLoTE.xml");

        // tag::european-LoLoTE-keystore[]
        // A certificate source which contains the signing certificate(s) for the
        // current list
        loloteSource.setCertificateSource(getSigningCertificatesForEuropeanLoLoTE());
        // end::european-LoLoTE-keystore[]

        // Optional : configure predicates
        // Default : none (select all)

        // ... omitted ...

        LoTEValidationJob.setLoLoTESources(loloteSource);
        // end::european-LoLoTE-source[]

        return loloteSource;
    }

    private CertificateSource getSigningCertificatesForEuropeanLoLoTE() {
        try {
            return new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12", getPassword());
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    private CertificateSource getSigningCertificatesForPIDProvidersList() {
        CertificateSource cs = new CommonCertificateSource();
        cs.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
                "MIIFWjCCBEKgAwIBAgISESH4uNBzewNTch8/fZTnHRxBMA0GCSqGSIb3DQEBCwUAMIGXMQswCQYDVQQGEwJGUjEwMC4GA1UECgwnQWdlbmNlIE5hdGlvbmFsZSBkZXMgVGl0cmVzIFPDqWN1cmlzw6lzMRcwFQYDVQQLDA4wMDAyIDEzMDAwMzI2MjExMC8GA1UEAwwoQXV0b3JpdMOpIGRlIENlcnRpZmljYXRpb24gUGVyc29ubmVzIEFBRTEKMAgGA1UEBRMBMzAeFw0xOTA5MDkxMTEyMzdaFw0yMjA5MDkxMTEyMzdaMHwxCzAJBgNVBAYTAkZSMQ0wCwYDVQQKDARBTlRTMRcwFQYDVQQLDA4wMDAyIDEzMDAwNzY2OTEjMCEGA1UEAwwaTWF0aGlldSBKT1JSWSAzMzEwMDAzODk4am0xEDAOBgNVBCoMB01hdGhpZXUxDjAMBgNVBAQMBUpPUlJZMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4iGy9/ATBcm6vIHI0vHgDfvkdaE2QicBcJFyRjexawI8fudrX5ffiMJZV5GCFBERvlu2IwctE0kVWpHGu0QMyLTNl4ZGDhjmgpX0u5zrF0KzKafKVzrKFbo4wr9+ZkUiJChHOWqejVDq40dVbRN5RzAFacIL2A6wyywmreAMnloh+vG2BEgTcj1lWWKc5rJx+ISYvG5j1bmbFYgNnI6RfbbM9QD7g1Bxw91kCPilT1P1L37Ay4kQQhLVDYFEsxBcSRkginO1iFFUlMendzj4RlxEcFwrGj26fIkLOmSOfAzWjkHvCcxgXydc6Y8zNpe1bYFIiNdsyFrK+GwzH26v0wIDAQABo4IBuDCCAbQwCQYDVR0TBAIwADAYBgNVHSAEETAPMA0GCyqBegGBSAMBAgMBMEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuYW50cy5nb3V2LmZyL2FudHNhdjMvYWNfcGVyc29ubmVzX2FhZV8zLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwLmFudHMuZ291di5mci9hbnRzYXYzL2FjX3BlcnNvbm5lc19hYWVfMzBBBggrBgEFBQcwAoY1aHR0cDovL3NwLmFudHMuZ291di5mci9hbnRzYXYzL2FjX3BlcnNvbm5lc19hYWVfMy5jZXIwDgYDVR0PAQH/BAQDAgZAMDcGCCsGAQUFBwEDBCswKTAIBgYEAI5GAQEwCAYGBACORgEEMBMGBgQAjkYBBjAJBgcEAI5GAQYBMCQGA1UdEQQdMBuBGW1hdGhpZXUuam9ycnlAc3NpLmdvdXYuZnIwHQYDVR0OBBYEFLGJXUMMaUx1wr2cJA7YxWipXF69MB8GA1UdIwQYMBaAFPVSfQ6yaX5wCwQ3h9ZQDSanC6SDMA0GCSqGSIb3DQEBCwUAA4IBAQCZidW3Bisie+Kf/NajL09gzeYhe0528GD//7z7RlMsMtEK3rCxW+El5lv37Zpi7WTZQN4qboP0K34y3QIzMt2BwUrGhP/u3ZBY/uuxXTD4p6DGZlbwrgnWNjAri2hS7J4T7n3LES/ieNDnj+EMa/d44wUMBQOayNnmDRneEwITljNnBTO1K0hkZwAdGx/5eH8dYEisNyjYAC+hSApN9sZqopU5Mb7Dautv6dqbRJQ2q/BuNqGPKKJKFtgpaVV9pFdetUVnAf/uBqGQ5iDWNCRyXnZ3gW7z747koSvNN2K/jWjA6u1c/cPgiUOBD3I9Ss0An8zcy5nsd+JJhTkOR8zG"));
        return cs;
    }

}
