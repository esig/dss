package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.ValidationDataContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xml.common.definition.XPathExpressionBuilder;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Tag;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
public class XAdESCrossCertificationDoubleLTAOldValDataTest extends PKIFactoryAccess {

    @RepeatedTest(10)
    void test() throws Exception {

        DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setValidationDataContainerType(ValidationDataContainerType.CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA);

        CertificateToken crossCertificate = getCertificateByPrimaryKey(2002, "external-ca");

        CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
        commonTrustedCertificateSource.addCertificate(crossCertificate);
        commonTrustedCertificateSource.addCertificate(getCertificate(ROOT_CA));
        commonTrustedCertificateSource.addCertificate(getCertificate(EE_GOOD_TSA));

        CommonCertificateVerifier customCertificateVerifier = (CommonCertificateVerifier) getCompleteCertificateVerifier();

        customCertificateVerifier.setCrlSource(pkiCRLSource());
        customCertificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        customCertificateVerifier.setAIASource(pkiAIASource());
        customCertificateVerifier.setTrustedCertSources(commonTrustedCertificateSource);

        XAdESService service = new XAdESService(customCertificateVerifier);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.SECOND, -1);
        service.setTspSource(getKeyStoreTSPSourceByNameAndTime(EE_GOOD_TSA, calendar.getTime()));

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(customCertificateVerifier);
        validator.setDetachedContents(Collections.singletonList(documentToSign));
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        // check no duplicate revocations for a certificate
        List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
        for (CertificateWrapper certificateWrapper : usedCertificates) {
            List<CertificateRevocationWrapper> certificateRevocationData = certificateWrapper.getCertificateRevocationData();
            List<String> revocationIds = new ArrayList<>();
            for (CertificateRevocationWrapper revocationWrapper : certificateRevocationData) {
                assertFalse(revocationIds.contains(revocationWrapper.getId()));
                revocationIds.add(revocationWrapper.getId());
            }
            assertEquals(certificateRevocationData.size(), revocationIds.size());
        }
        assertEquals(7, usedCertificates.size());

        List<RelatedCertificateWrapper> relatedCertificatesFirstLTA = signature.foundCertificates().getRelatedCertificates();
        List<RelatedRevocationWrapper> relatedRevocationsFirstLTA = signature.foundRevocations().getRelatedRevocationData();

        customCertificateVerifier = (CommonCertificateVerifier) getCompleteCertificateVerifier();

        customCertificateVerifier.setCrlSource(pkiCRLSource());
//        customCertificateVerifier.setTrustedCertSources(commonTrustedCertificateSource);

        service = new XAdESService(customCertificateVerifier);

        calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.SECOND, 1);
        service.setTspSource(getKeyStoreTSPSourceByNameAndTime(EE_GOOD_TSA, calendar.getTime()));

        XAdESSignatureParameters extendParameters = new XAdESSignatureParameters();
        extendParameters.setDetachedContents(Collections.singletonList(documentToSign));
        extendParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        extendParameters.setValidationDataContainerType(ValidationDataContainerType.CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA);

        DSSDocument doubleLTADoc = service.extendDocument(signedDocument, extendParameters);
        // doubleLTADoc.save("target/doubleLTA.xml");

        validator = SignedDocumentValidator.fromDocument(doubleLTADoc);

        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setDetachedContents(Collections.singletonList(documentToSign));
        reports = validator.validateDocument();

        diagnosticData = reports.getDiagnosticData();
        signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        List<RelatedCertificateWrapper> relatedCertificatesSecondLTA = signature.foundCertificates().getRelatedCertificates();
        List<RelatedRevocationWrapper> relatedRevocationsSecondLTA = signature.foundRevocations().getRelatedRevocationData();

        assertEquals(relatedCertificatesFirstLTA.size(), relatedCertificatesSecondLTA.size());
        assertEquals(relatedRevocationsFirstLTA.size(), relatedRevocationsSecondLTA.size());

        Collection<RelatedCertificateWrapper> tstValidationDataCerts = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
        assertTrue(Utils.isCollectionEmpty(tstValidationDataCerts));

        Collection<RelatedRevocationWrapper> tstValidationDataRevocations = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
        assertTrue(Utils.isCollectionEmpty(tstValidationDataRevocations));

        Collection<RelatedCertificateWrapper> anyValidationDataCerts = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA);
        assertTrue(Utils.isCollectionEmpty(anyValidationDataCerts));

        Collection<RelatedRevocationWrapper> anyValidationDataRevocations = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA);
        assertTrue(Utils.isCollectionEmpty(anyValidationDataRevocations));

        Document document = DomUtils.buildDOM(doubleLTADoc);
        assertNotNull(document);

        Element timeStampValidationDataElement = DomUtils.getElement(document, new XPathExpressionBuilder().all().element(XAdES141Element.TIMESTAMP_VALIDATION_DATA).build());
        assertNull(timeStampValidationDataElement);

        Element anyValidationDataElement = DomUtils.getElement(document, new XPathExpressionBuilder().all().element(XAdES141Element.ANY_VALIDATION_DATA).build());
        assertNull(anyValidationDataElement);

    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER_CROSS_CERTIF;
    }

}
