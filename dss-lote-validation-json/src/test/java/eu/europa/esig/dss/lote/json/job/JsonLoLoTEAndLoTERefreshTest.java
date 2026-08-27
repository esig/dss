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
package eu.europa.esig.dss.lote.json.job;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.json.MockDataLoader;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.job.DownloadInfoRecord;
import eu.europa.esig.dss.model.job.ValidationInfoRecord;
import eu.europa.esig.dss.model.lote.LoLoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.model.lote.record.LoTEParsingInfoRecord;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonLoLoTEAndLoTERefreshTest {

    private static final String LOLOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUlistofthelists";

    @TempDir
    File cacheDirectory;

    @Test
    void test() {

        FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoLoTESources(europeanLoLoTE());
        job.setLoTESources(registrarLoTE());
        job.setOfflineDataLoader(offlineFileLoader);
        job.setTrustedEntitiesCertificateSource(new TrustedEntitiesCertificateSource());

        job.setDebug(true);

        job.offlineRefresh();

        checks(job, Indication.TOTAL_PASSED);

        job.offlineRefresh();

        checks(job, Indication.TOTAL_PASSED);
    }


    private FileCacheDataLoader getOfflineFileLoader(Map<String, DSSDocument> urlMap) {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
        offlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
        offlineFileLoader.setFileCacheDirectory(cacheDirectory);
        return offlineFileLoader;
    }

    private Map<String, DSSDocument> correctUrlMap() {
        Map<String, DSSDocument> urlMap = new HashMap<>();
        urlMap.put("EU", new FileDocument("src/test/resources/eu-lolote.json"));
        urlMap.put("reg", new FileDocument("src/test/resources/registrar.jwt"));
        return urlMap;
    }

    private void checks(LoTEValidationJob job, Indication expectedIndication) {
        LoTEValidationJobSummary summary = job.getSummary();
        assertNotNull(summary);
        assertEquals(1, summary.getNumberOfProcessedLoLoTEs());
        List<LoLoTEInfo> loloteInfos = summary.getLoLoTEInfos();
        assertEquals(1, loloteInfos.size());
        LoLoTEInfo loloteInfo = loloteInfos.get(0);
        DownloadInfoRecord downloadCacheInfo = loloteInfo.getDownloadCacheInfo();
        assertNotNull(downloadCacheInfo);
        assertNotNull(downloadCacheInfo.getLastStateTransitionTime());
        assertTrue(downloadCacheInfo.isSynchronized());
        LoTEParsingInfoRecord parsingCacheInfo = loloteInfo.getParsingCacheInfo();
        assertNotNull(parsingCacheInfo);
        assertTrue(parsingCacheInfo.isSynchronized());

        assertEquals(1, parsingCacheInfo.getVersion());
        assertEquals(1, parsingCacheInfo.getSequenceNumber());

        ValidationInfoRecord validationCacheInfo = loloteInfo.getValidationCacheInfo();
        assertNotNull(validationCacheInfo);
        assertTrue(validationCacheInfo.isSynchronized());

        // LoLoTE
        assertEquals(expectedIndication, validationCacheInfo.getIndication());
        assertNotNull(validationCacheInfo.getSigningCertificate());
        assertNotNull(validationCacheInfo.getSigningTime());

        assertEquals(1, loloteInfo.getChildrenInfos().size());

        assertEquals(1, summary.getOtherLoTEInfos().size());

        LoTEInfo loteInfo = summary.getOtherLoTEInfos().get(0);

        downloadCacheInfo = loteInfo.getDownloadCacheInfo();
        assertNotNull(downloadCacheInfo);
        assertNotNull(downloadCacheInfo.getLastStateTransitionTime());
        assertTrue(downloadCacheInfo.isSynchronized());

        parsingCacheInfo = loteInfo.getParsingCacheInfo();
        assertNotNull(parsingCacheInfo);
        assertFalse(parsingCacheInfo.isError());
        assertNull(parsingCacheInfo.getExceptionMessage());
        assertNull(parsingCacheInfo.getExceptionStackTrace());
        assertTrue(parsingCacheInfo.isResultExist());
        assertTrue(Utils.isCollectionNotEmpty(parsingCacheInfo.getStructureValidationMessages()));
        assertTrue(parsingCacheInfo.getStructureValidationMessages().stream().anyMatch(m -> m.contains("required properties are missing: iat")));

        validationCacheInfo = loteInfo.getValidationCacheInfo();
        assertNotNull(validationCacheInfo);
        assertTrue(validationCacheInfo.isSynchronized());
        assertFalse(validationCacheInfo.isValid()); // not JAdES-B-B
        assertNotNull(validationCacheInfo.getSigningCertificate());
        assertNull(validationCacheInfo.getSigningTime()); // no signing-time
    }

    private LoLoTESource europeanLoLoTE() {
        LoLoTESource lolote = new LoLoTESource();
        lolote.setUrl("EU");
        CertificateSource certificateSource = new CommonCertificateSource();
        certificateSource.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/lolote-cert.cer")));
        lolote.setCertificateSource(certificateSource);
        lolote.setLolotePredicate(otherListPointer -> LOLOTE_TYPE.equals(otherListPointer.getType()));
        lolote.setLotePredicate(otherListPointer -> !LOLOTE_TYPE.equals(otherListPointer.getType()));
        return lolote;
    }

    private LoTESource registrarLoTE() {
        LoTESource lote = new LoTESource();
        lote.setUrl("reg");
        CertificateSource certificateSource = new CommonCertificateSource();
        certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIICDDCCAbGgAwIBAgIUYUPFTqKy7+8FSzt9Yf0jMISRE7QwCgYIKoZIzj0EAwIwWzELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMRQwEgYDVQQKDAtUcnVzdCBMaXN0czEUMBIGA1UEAwwLTG9URSBTaWduZXIwHhcNMjYwMzIzMTAwNjM2WhcNMzYwMzIwMTAwNjM2WjBbMQswCQYDVQQGEwJERTEPMA0GA1UECAwGQmVybGluMQ8wDQYDVQQHDAZCZXJsaW4xFDASBgNVBAoMC1RydXN0IExpc3RzMRQwEgYDVQQDDAtMb1RFIFNpZ25lcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNzQE+ajQQOr9P58E8Uz+3hkmgevbjPoBe8iVSyYeBBxePGqozPadw2PBp5l6g1lMyJVFdwA/AK4pTyBzrm9yhijUzBRMB0GA1UdDgQWBBQRD8DxrfaP2KSAIDrU8cPWS1Ul6jAfBgNVHSMEGDAWgBQRD8DxrfaP2KSAIDrU8cPWS1Ul6jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCq3sEiM+xZO+a63p3zaR5dbS4XoR+blZX2ZKmCX3llbgIhANBGjCx5ApJnpXnNV9r0f3MTNtMG++8b+/59paf77BQb"));
        lote.setCertificateSource(certificateSource);
        return lote;
    }

}