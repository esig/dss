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
package eu.europa.esig.dss.lote.xml.job;

import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.lote.xml.MockDataLoader;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.job.InfoRecord;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.validation.job.cache.state.CacheStateEnum;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlLoTEValidationJobTransitionTest {

    @TempDir
    File cacheDirectory;

    private static final DSSDocument PUBEAA = new FileDocument("src/test/resources/lote-pubeaa.xml");
    private static final DSSDocument PUBEAA_NULL = null;
    private static final DSSDocument PUBEAA_NOT_XML = new FileDocument("src/test/resources/lote-pubeaa.json");
    private static final DSSDocument PUBEAA_BROKEN_SIG = new FileDocument("src/test/resources/lote-pubeaa-broken-sig.xml");
    private static final DSSDocument PUBEAA_NOT_COMPLIANT = new FileDocument("src/test/resources/lote-pubeaa-not-compliant.xml");
    private static final DSSDocument PUBEAA_NOT_PARSABLE = new FileDocument("src/test/resources/lote-pubeaa-not-parsable.xml");

    @Test
    void nullDoc() {

        String url = "null-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NULL, url));

        job.onlineRefresh();

        LoTEValidationJobSummary firstSummary = job.getSummary();
        LoTEInfo firstPUBEAA = firstSummary.getOtherLoTEInfos().get(0);
        assertNull(firstPUBEAA.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        checkSummary(firstSummary, CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

        // Wait
        Calendar nextMilliSecond = Calendar.getInstance();
        nextMilliSecond.add(Calendar.MILLISECOND, 1);
        await().atMost(1, TimeUnit.SECONDS).until(() -> Calendar.getInstance().getTime().compareTo(nextMilliSecond.getTime()) > 0);

        job.onlineRefresh();

        LoTEValidationJobSummary secondSummary = job.getSummary();
        LoTEInfo secondPUBEAA = secondSummary.getOtherLoTEInfos().get(0);
        assertNull(secondPUBEAA.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        checkSummary(secondSummary, CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

        // Keep the first error time
        assertEquals(firstPUBEAA.getDownloadCacheInfo().getExceptionFirstOccurrenceTime(), secondPUBEAA.getDownloadCacheInfo().getExceptionFirstOccurrenceTime());
        assertEquals(firstPUBEAA.getDownloadCacheInfo().getExceptionMessage(), secondPUBEAA.getDownloadCacheInfo().getExceptionMessage());
    }

    @Test
    void nullDocNullCertSource() {

        String url = "null-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        LoTESource loteSource = new LoTESource();
        loteSource.setUrl(url);
        job.setLoTESources(loteSource);
        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NULL, url));

        job.onlineRefresh();

        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

        job.onlineRefresh();

        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);
    }

    @Test
    void nullToValidDoc() {

        String url = "null-to-valid-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setTrustedEntitiesCertificateSource(new TrustedEntitiesCertificateSource());
        job.setLoTESources(getLoTESource(url));

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NULL, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        LoTEValidationJobSummary summarySuccess = job.getSummary();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NULL, url));
        job.onlineRefresh();
        LoTEValidationJobSummary summaryFail = job.getSummary();
        checkSummary(summaryFail, CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        LoTEInfo successTlInfo = summarySuccess.getOtherLoTEInfos().get(0);
        LoTEInfo failTlInfo = summaryFail.getOtherLoTEInfos().get(0);

        assertEquals(successTlInfo.getDownloadCacheInfo().getLastStateTransitionTime(), failTlInfo.getDownloadCacheInfo().getLastStateTransitionTime());
        assertEquals(successTlInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime(), failTlInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertNotEquals(successTlInfo.getDownloadCacheInfo().getExceptionMessage(), failTlInfo.getDownloadCacheInfo().getExceptionMessage());

        assertEquals(successTlInfo.getParsingCacheInfo().getLastStateTransitionTime(), failTlInfo.getParsingCacheInfo().getLastStateTransitionTime());
        assertEquals(successTlInfo.getValidationCacheInfo().getLastStateTransitionTime(), failTlInfo.getValidationCacheInfo().getLastStateTransitionTime());

    }

    @Test
    void lastDownloadAttempTest() {
        String url = "null-to-valid-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setTrustedEntitiesCertificateSource(new TrustedEntitiesCertificateSource());
        job.setLoTESources(getLoTESource(url));

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NULL, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

        LoTEValidationJobSummary summary = job.getSummary();
        LoTEInfo loteInfo = summary.getOtherLoTEInfos().get(0);

        assertNull(loteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertNotNull(loteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
        assertNotNull(loteInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime());
        assertEquals(loteInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime(), loteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
        summary = job.getSummary();
        loteInfo = summary.getOtherLoTEInfos().get(0);

        assertNull(loteInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime());
        assertNotNull(loteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
        assertNotNull(loteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertEquals(loteInfo.getDownloadCacheInfo().getLastStateTransitionTime(), loteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NULL, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
        summary = job.getSummary();
        loteInfo = summary.getOtherLoTEInfos().get(0);

        assertNotNull(loteInfo.getDownloadCacheInfo().getLastSuccessSynchronizationTime());
        assertNotNull(loteInfo.getDownloadCacheInfo().getLastStateTransitionTime());
        assertNotNull(loteInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime());
        assertEquals(loteInfo.getDownloadCacheInfo().getExceptionLastOccurrenceTime(), loteInfo.getDownloadCacheInfo().getLastDownloadAttemptTime());

    }

    @Test
    void validToNulldDoc() {

        String url = "valid-to-null-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setTrustedEntitiesCertificateSource(new TrustedEntitiesCertificateSource());
        job.setLoTESources(getLoTESource(url));

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NULL, url));
        job.onlineRefresh();
        // valid parsing and signature are still present
        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
    }

    @Test
    void validToNonCompliantDoc() {

        String url = "valid-to-null-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setTrustedEntitiesCertificateSource(new TrustedEntitiesCertificateSource());
        job.setLoTESources(getLoTESource(url));

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NOT_COMPLIANT, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
    }

    @Test
    void validToNonParsableDoc() {

        String url = "valid-to-null-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setTrustedEntitiesCertificateSource(new TrustedEntitiesCertificateSource());
        job.setLoTESources(getLoTESource(url));

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NOT_PARSABLE, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
    }

    @Test
    void nullToNonCompliantAndThenValidDoc() {

        String url = "null-to-valid-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setTrustedEntitiesCertificateSource(new TrustedEntitiesCertificateSource());
        job.setLoTESources(getLoTESource(url));

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NULL, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NOT_COMPLIANT, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);

        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));
        job.onlineRefresh();
        checkSummary(job.getSummary(), CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED, CacheStateEnum.SYNCHRONIZED);
    }

    @Test
    void noXml() {

        String url = "no-xml";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NOT_XML, url));

        job.onlineRefresh();

        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);
    }

    @Test
    void notParsable() {

        String url = "no-parsable";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NOT_PARSABLE, url));

        job.onlineRefresh();

        checkSummary(job.getSummary(), CacheStateEnum.ERROR, CacheStateEnum.REFRESH_NEEDED, CacheStateEnum.REFRESH_NEEDED);
    }

    @Test
    void notCompliant() {

        String url = "no-compliant";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_NOT_COMPLIANT, url));

        job.onlineRefresh();

        checkSummary(job.getSummary(), CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED);
    }

    @Test
    void validDoc() {

        String url = "valid-doc";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA, url));

        job.onlineRefresh();

        checkSummary(job.getSummary(), CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED);
    }

    @Test
    void brokenSig() {

        String url = "broken-sig";

        LoTEValidationJob job = new LoTEValidationJob();
        job.setLoTESources(getLoTESource(url));
        job.setOnlineDataLoader(getOnlineDataLoader(PUBEAA_BROKEN_SIG, url));

        job.onlineRefresh();

        checkSummary(job.getSummary(), CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED, CacheStateEnum.DESYNCHRONIZED);
    }

    private LoTESource getLoTESource(String url) {
        LoTESource loteSource = new LoTESource();
        loteSource.setUrl(url);
        CertificateSource certificateSource = new CommonCertificateSource();
        certificateSource.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/lote-signer.cer")));
        loteSource.setCertificateSource(certificateSource);
        return loteSource;
    }

    private DSSFileLoader getOnlineDataLoader(DSSDocument doc, String url) {
        FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        Map<String, DSSDocument> onlineMap = new HashMap<>();
        onlineMap.put(url, doc);
        onlineFileLoader.setDataLoader(new MockDataLoader(onlineMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);
        return onlineFileLoader;
    }

    private void checkSummary(LoTEValidationJobSummary summary, CacheStateEnum download, CacheStateEnum parsing, CacheStateEnum validation) {
        assertNotNull(summary);
        List<LoTEInfo> loteInfos = summary.getOtherLoTEInfos();
        assertEquals(1, loteInfos.size());
        assertEquals(1, summary.getNumberOfProcessedLoTEs());
        LoTEInfo loteInfo = loteInfos.get(0);

        checkCacheStateEnum(download, loteInfo.getDownloadCacheInfo());
        checkCacheStateEnum(parsing, loteInfo.getParsingCacheInfo());
        checkCacheStateEnum(validation, loteInfo.getValidationCacheInfo());
    }

    private void checkCacheStateEnum(CacheStateEnum cacheState, InfoRecord cacheInfo) {
        switch (cacheState) {
            case REFRESH_NEEDED:
                assertTrue(cacheInfo.isRefreshNeeded());
                assertFalse(cacheInfo.isDesynchronized());
                assertFalse(cacheInfo.isSynchronized());
                assertFalse(cacheInfo.isError());
                assertFalse(cacheInfo.isToBeDeleted());
                break;
            case DESYNCHRONIZED:
                assertFalse(cacheInfo.isRefreshNeeded());
                assertTrue(cacheInfo.isDesynchronized());
                assertFalse(cacheInfo.isSynchronized());
                assertFalse(cacheInfo.isError());
                assertFalse(cacheInfo.isToBeDeleted());
                break;
            case SYNCHRONIZED:
                assertFalse(cacheInfo.isRefreshNeeded());
                assertFalse(cacheInfo.isDesynchronized());
                assertTrue(cacheInfo.isSynchronized());
                assertFalse(cacheInfo.isError());
                assertFalse(cacheInfo.isToBeDeleted());
                break;
            case ERROR:
                assertFalse(cacheInfo.isRefreshNeeded());
                assertFalse(cacheInfo.isDesynchronized());
                assertFalse(cacheInfo.isSynchronized());
                assertTrue(cacheInfo.isError());
                assertFalse(cacheInfo.isToBeDeleted());
                break;
            case TO_BE_DELETED:
                assertFalse(cacheInfo.isRefreshNeeded());
                assertFalse(cacheInfo.isDesynchronized());
                assertFalse(cacheInfo.isSynchronized());
                assertFalse(cacheInfo.isError());
                assertTrue(cacheInfo.isToBeDeleted());
                break;
            default:
                throw new DSSException("Illegal state.");
        }
    }

}
