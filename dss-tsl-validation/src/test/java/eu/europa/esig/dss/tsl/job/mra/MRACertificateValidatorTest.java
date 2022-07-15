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
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MRACertificateValidatorTest extends AbstractMRALOTLTest {

    @Test
    @Override
    public void test() {
        TLValidationJob tlValidationJob = new TLValidationJob();

        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl(LOTL_LOCATION);
        lotlSource.setMraSupport(true);

        CommonTrustedCertificateSource lotlKeystore = new CommonTrustedCertificateSource();
        lotlKeystore.addCertificate(getCertificate(SIGNER_LOTL_NAME));
        lotlSource.setCertificateSource(lotlKeystore);

        lotlSource.setTlPredicate(TLPredicateFactory.createPredicateWithCustomTSLType("http://example/TSLType/CCgeneric"));

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
