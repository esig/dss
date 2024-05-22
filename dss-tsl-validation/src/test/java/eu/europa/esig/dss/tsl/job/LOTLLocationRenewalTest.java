/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.job;

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.PivotInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogLOTLLocationChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class LOTLLocationRenewalTest {

    private static final String KS_TYPE = "PKCS12";
    private static final char[] KS_PASSWORD = "password".toCharArray();

    private static String lotlLocationPath;

    private static Map<String, Collection<String>> lotlLocations;
    private static Map<String, DSSDocument> pivotMap;

    private static Map<String, CertificateSource> keyStoreMap;

    private static Map<String, Collection<String>> ojLotlMap;

    private static Collection<String> newLOTLLocations;

    private static String newOJKeystore;

    private static FileCacheDataLoader fileLoader;
    private static CacheCleaner cacheCleaner;

    @BeforeAll
    public static void initBeforeAll() throws IOException {
        lotlLocations = new LinkedHashMap<>();
        pivotMap = new LinkedHashMap<>();
        keyStoreMap = new LinkedHashMap<>();
        ojLotlMap = new LinkedHashMap<>();

        lotlLocationPath = getLotlLocationPath();

        lotlLocations.put("lotl_test_loc_01.xml",
                Arrays.asList(
                        "lotl_test_OJ_1_pivot_01.xml",
                        "lotl_test_OJ_1_pivot_02.xml",
                        "lotl_test_OJ_1_pivot_03.xml",
                        "lotl_test_OJ_2_pivot_01.xml",
                        "lotl_test_OJ_2_pivot_02.xml"
                )
        );
        lotlLocations.put("lotl_test_loc_02.xml",
                Arrays.asList(
                        "lotl_test_OJ_2_pivot_01.xml",
                        "lotl_test_OJ_2_pivot_02.xml",
                        "lotl_test_OJ-2_reset_pivot.xml"
                )
        );

        pivotMap.put("lotl_test_loc_01.xml", new FileDocument("src/test/resources/pivots/lotl_test_loc_01.xml"));
        pivotMap.put("lotl_test_OJ_1_pivot_01.xml", new FileDocument("src/test/resources/pivots/lotl_test_OJ_1_pivot_01.xml"));
        pivotMap.put("lotl_test_OJ_1_pivot_02.xml", new FileDocument("src/test/resources/pivots/lotl_test_OJ_1_pivot_02.xml"));
        pivotMap.put("lotl_test_OJ_1_pivot_03.xml", new FileDocument("src/test/resources/pivots/lotl_test_OJ_1_pivot_03.xml"));
        pivotMap.put("lotl_test_OJ_2_pivot_01.xml", new FileDocument("src/test/resources/pivots/lotl_test_OJ_2_pivot_01.xml"));
        pivotMap.put("lotl_test_OJ_2_pivot_02.xml", new FileDocument("src/test/resources/pivots/lotl_test_OJ_2_pivot_02.xml"));
        pivotMap.put("lotl_test_OJ-2_reset_pivot.xml", new FileDocument("src/test/resources/pivots/lotl_test_OJ-2_reset_pivot.xml"));

        keyStoreMap.put("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG",
                new KeyStoreCertificateSource("src/test/resources/pivots/keystore_OJ1.p12", KS_TYPE, KS_PASSWORD)
        );
        keyStoreMap.put("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2023.999.01.0001.01.ENG",
                new KeyStoreCertificateSource("src/test/resources/pivots/keystore_OJ2.p12", KS_TYPE, KS_PASSWORD)
        );

        ojLotlMap.put("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG",
                Arrays.asList(
                        "lotl_test_OJ_1_pivot_01.xml",
                        "lotl_test_OJ_1_pivot_02.xml",
                        "lotl_test_OJ_1_pivot_03.xml",
                        "lotl_test_OJ_2_pivot_01.xml",
                        "lotl_test_OJ_2_pivot_02.xml"
                )
        );
        ojLotlMap.put("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2023.999.01.0001.01.ENG",
                Arrays.asList(
                        "lotl_test_OJ_2_pivot_01.xml",
                        "lotl_test_OJ_2_pivot_02.xml",
                        "lotl_test_OJ-2_reset_pivot.xml"
                )
        );

        newLOTLLocations = Arrays.asList(
                "lotl_test_loc_02.xml",
                "lotl_test_OJ_1_pivot_03.xml",
                "lotl_test_OJ_2_pivot_01.xml",
                "lotl_test_OJ_2_pivot_02.xml",
                "lotl_test_OJ-2_reset_pivot.xml");

        newOJKeystore = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2023.999.01.0001.01.ENG";

        File cacheDirectory = new File("target/cache");

        fileLoader = new FileCacheDataLoader();
        fileLoader.setCacheExpirationTime(0);
        fileLoader.setFileCacheDirectory(cacheDirectory);

        cacheCleaner = new CacheCleaner();
        cacheCleaner.setDSSFileLoader(fileLoader);
        cacheCleaner.setCleanFileSystem(true);
    }

    private static String getLotlLocationPath() {
        try {
            TrustStatusListType trustStatusListType = TrustedListFacade.newFacade().unmarshall(
                    new File("src/test/resources/pivots/lotl_test_OJ_1_pivot_01.xml"));
            String tslLocation = trustStatusListType.getSchemeInformation()
                    .getPointersToOtherTSL().getOtherTSLPointer().get(0).getTSLLocation();
            return tslLocation.substring(0, tslLocation.lastIndexOf("/")) + "/";
        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private static Stream<Arguments> data() {
        Object[] locations = lotlLocations.keySet().toArray(new String[0]);
        Object[] pivotUrls = pivotMap.keySet().toArray(new String[0]);
        Object[] ojUrls = keyStoreMap.keySet().toArray(new String[0]);
        Object[] ojKeystores = keyStoreMap.values().toArray(new CertificateSource[0]);
        return random(locations, pivotUrls, ojUrls, ojKeystores);
    }

    static Stream<Arguments> random(Object[] locations, Object[] lotlUrls, Object[] ojUrls, Object[] ojKeystores) {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < lotlUrls.length; i++) {
            for (int h = 0; h < ojUrls.length; h++) {
                if (ojLotlMap.get((String) ojUrls[h]).contains((String) lotlUrls[i])) {
                    for (int m = 0; m < locations.length; m++) {
                        if (lotlLocations.get((String) locations[m]).contains((String) lotlUrls[i])) {
                            args.add(Arguments.of(locations[m], lotlUrls[i], ojUrls[h], ojKeystores[h]));
                            if (h == 0) {
                                args.add(Arguments.of(locations[m], lotlUrls[i], null, ojKeystores[h]));
                            }
                        }
                    }
                }
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "OJ test {index} : {0} - {1} - {2}")
    @MethodSource("data")
    public void test(String location, String pivotlUrl, String ojUrl, CertificateSource ojKeystore) {
        HashMap<String, DSSDocument> cacheMap = getCacheMap();
        cacheMap.put(lotlLocationPath + location, pivotMap.get(pivotlUrl));
        fileLoader.setDataLoader(new MockDataLoader(cacheMap));

        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl(lotlLocationPath + location);
        lotlSource.setCertificateSource(ojKeystore);
        if (ojUrl != null) {
            lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(ojUrl));
        }
        lotlSource.setPivotSupport(true);

        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();

        TLValidationJob tlValidationJob = new TLValidationJob();
        tlValidationJob.setOfflineDataLoader(fileLoader);
        tlValidationJob.setCacheCleaner(cacheCleaner);

        FallBackAlertDetector ojUrlDetection = new FallBackAlertDetector(new OJUrlChangeDetection(lotlSource));
        FallBackAlertDetector lotlLocationDetection = new FallBackAlertDetector(new LOTLLocationChangeDetection(lotlSource));

        tlValidationJob.setLOTLAlerts(Arrays.asList(ojUrlAlert(ojUrlDetection), lotlLocationAlert(lotlLocationDetection)));
        tlValidationJob.setListOfTrustedListSources(lotlSource);
        tlValidationJob.setTrustedListCertificateSource(trustedListsCertificateSource);
        tlValidationJob.offlineRefresh();

        TLValidationJobSummary summary = tlValidationJob.getSummary();
        List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
        assertEquals(1, lotlInfos.size());

        LOTLInfo lotlInfo = lotlInfos.get(0);
        assertTrue(lotlInfo.getDownloadCacheInfo().isSynchronized());
        assertTrue(lotlInfo.getParsingCacheInfo().isSynchronized());
        assertTrue(lotlInfo.getValidationCacheInfo().isSynchronized());
        assertEquals(Indication.TOTAL_PASSED, lotlInfo.getValidationCacheInfo().getIndication());
        for (PivotInfo pivotInfo : lotlInfo.getPivotInfos()) {
            assertTrue(pivotInfo.getDownloadCacheInfo().isSynchronized());
            assertTrue(pivotInfo.getParsingCacheInfo().isSynchronized());
            assertTrue(pivotInfo.getValidationCacheInfo().isSynchronized());
            assertEquals(Indication.TOTAL_PASSED, pivotInfo.getValidationCacheInfo().getIndication());
        }

        assertEquals(ojUrl != null && !newOJKeystore.equals(ojUrl) && ojLotlMap.get(newOJKeystore).contains(pivotlUrl), ojUrlDetection.detected);
        assertEquals(!newLOTLLocations.contains(location) && newLOTLLocations.contains(pivotlUrl), lotlLocationDetection.detected);
    }

    private HashMap<String, DSSDocument> getCacheMap() {
        HashMap<String, DSSDocument> hashMap = new HashMap<>();
        for (Map.Entry<String, DSSDocument> entry : pivotMap.entrySet()) {
            hashMap.put(lotlLocationPath + entry.getKey(), entry.getValue());
        }
        return hashMap;
    }

    private LOTLAlert ojUrlAlert(AlertDetector<LOTLInfo> ojUrlDetection) {
        LogOJUrlChangeAlertHandler handler = new LogOJUrlChangeAlertHandler();
        return new LOTLAlert(ojUrlDetection, handler);
    }

    private LOTLAlert lotlLocationAlert(AlertDetector<LOTLInfo> lotlLocationDetection) {
        LogLOTLLocationChangeAlertHandler handler = new LogLOTLLocationChangeAlertHandler();
        return new LOTLAlert(lotlLocationDetection, handler);
    }

    private static class FallBackAlertDetector implements AlertDetector<LOTLInfo> {

        private boolean detected = false;

        private final AlertDetector<LOTLInfo> alertDetector;

        public FallBackAlertDetector(AlertDetector<LOTLInfo> alertDetector) {
            this.alertDetector = alertDetector;
        }

        @Override
        public boolean detect(LOTLInfo info) {
            boolean detected = alertDetector.detect(info);
            this.detected = detected;
            return detected;
        }

    }

}
