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
package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MRACertificateValidatorTest extends AbstractMRALOTLTest {

    @Test
    @Override
    void test() {
        TLValidationJob tlValidationJob = new TLValidationJob();

        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl(LOTL_LOCATION);
        lotlSource.setMraSupport(true);

        CommonTrustedCertificateSource lotlKeystore = new CommonTrustedCertificateSource();
        lotlKeystore.addCertificate(getCertificate(SIGNER_LOTL_NAME));
        lotlSource.setCertificateSource(lotlKeystore);

        lotlSource.setTlPredicate(TLPredicateFactory.createPredicateWithCustomTSLType("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/ZZlist"));

        tlValidationJob.setListOfTrustedListSources(lotlSource);

        Map<String, byte[]> inMemoryMap = new HashMap<>();
        inMemoryMap.put(LOTL_LOCATION, DSSUtils.toByteArray(createZZLOTL()));
        inMemoryMap.put(ZZ_TL_LOCATION, DSSUtils.toByteArray(createZZTL()));
        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setDataLoader(new MemoryDataLoader(inMemoryMap));
        fileCacheDataLoader.setCacheExpirationTime(0);

        tlValidationJob.setOfflineDataLoader(fileCacheDataLoader);

        TrustedListsCertificateSource trustedCertificateSource = new TrustedListsCertificateSource();
        tlValidationJob.setTrustedListCertificateSource(trustedCertificateSource);

        tlValidationJob.offlineRefresh();

        assertEquals(1, trustedCertificateSource.getCertificates().size());


        CertificateToken signingCert = getCertificate(getSignerName());

        CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
        completeCertificateVerifier.addTrustedCertSources(trustedCertificateSource);

        CertificateValidator certificateValidator = CertificateValidator.fromCertificate(signingCert);
        certificateValidator.setCertificateVerifier(completeCertificateVerifier);
        CertificateReports reports = certificateValidator.validate();

        assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD, reports.getSimpleReport().getQualificationAtCertificateIssuance());
        assertEquals(CertificateQualification.QCERT_FOR_ESIG_QSCD, reports.getSimpleReport().getQualificationAtValidationTime());
    }

    @Override
    protected Indication getFinalIndication() {
        return null;
    }

    @Override
    protected SignatureQualification getFinalSignatureQualification() {
        return null;
    }

    @Override
    protected boolean isEnactedMRA() {
        return false;
    }

    @Override
    protected String getMRAEnactedTrustServiceLegalIdentifier() {
        return null;
    }

}
