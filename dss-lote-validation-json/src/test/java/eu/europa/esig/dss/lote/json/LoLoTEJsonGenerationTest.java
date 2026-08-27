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
package eu.europa.esig.dss.lote.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateApprovalStatusProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlListOfTrustedEntities;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatus;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatusEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class LoLoTEJsonGenerationTest extends PKIFactoryAccess {

    private static final String PKI_NAME = "pid-providers";

    private static final String LOLOTE_LOCATION_URL = "https://test.test/lolote";
    private static final String LOTE_LOCATION_URL = "https://test.test/lote-pid";

    // TODO : change to real ones
    private static final String EU_LIST_OF_LISTS_TYPE = "http://uri.etsi.org/19602/LoTEType/EUlistofthelists";
    private static final String EU_LIST_OF_LISTS_STATUS_DETERMINATION_APPROACH = "http://uri.etsi.org/19602/ListOfLists/StatusDetn/EU";
    private static final String EU_LIST_OF_LISTS_SCHEME_TYPE_COMMUNITY_RULES = "http://uri.etsi.org/19602/ListOfLists/schemerules/EU";

    private static final String PID_PROVIDERS_LIST_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";
    private static final String PID_SERVICE_TYPE_IDENTIFIER = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    private static final String PID_LIST_STATUS_DETERMINATION_APPROACH = "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU";
    private static final String PID_LIST_SCHEME_TYPE_COMMUNITY_RULES = "http://uri.etsi.org/19602/PIDProviders/schemerules/EU";

    private static Map<String, DSSDocument> urlMap;
    private static FileCacheDataLoader onlineFileLoader;
    private static File cacheDirectory;

    private static final String PID_CERTIFICATE = "Test-PID";
    private CertificateToken pidCertificate;

    private static final String LOLOTE_SIGNER_CERTIFICATE = "LoLoTE-Signer";
    private static final String LOTE_SIGNER_CERTIFICATE = "LoTE-Signer";

    private String signer;

    @BeforeEach
    void init() {
        urlMap = new HashMap<>();

        cacheDirectory = new File("target/cache");

        onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);

        pidCertificate = getCertificate(PID_CERTIFICATE);
    }

    @Test
    void test() {
        DSSDocument lolote = createLoLoTE();
        DSSDocument lote = createLoTE();

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();

        LoTEValidationJob validationJob = new LoTEValidationJob();
        validationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);

        urlMap.put(LOLOTE_LOCATION_URL, lolote);
        urlMap.put(LOTE_LOCATION_URL, lote);
        validationJob.setOnlineDataLoader(onlineFileLoader);

        LoLoTESource loloteSource = new LoLoTESource();
        loloteSource.setUrl(LOLOTE_LOCATION_URL);
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(getCertificate(LOLOTE_SIGNER_CERTIFICATE));
        loloteSource.setCertificateSource(trustedCertificateSource);
        loloteSource.setLotePredicate(otherListPointer ->
                PID_PROVIDERS_LIST_TYPE.equals(otherListPointer.getType()));
        validationJob.setLoLoTESources(loloteSource);

        validationJob.onlineRefresh();

        LoTEValidationJobSummary summary = validationJob.getSummary();
        assertEquals(1, trustedEntitiesCertificateSource.getNumberOfCertificates());
        assertEquals(Indication.TOTAL_PASSED, summary.getLoLoTEInfos().get(0).getValidationCacheInfo().getIndication());

        assertEquals(1, trustedEntitiesCertificateSource.getCertificates().size());

        CertificateValidator validator = CertificateValidator.fromCertificate(pidCertificate);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setTrustedCertSources(trustedEntitiesCertificateSource);
        validator.setCertificateVerifier(certificateVerifier);

        CertificateReports reports = validator.validate();

        String certId = pidCertificate.getDSSIdAsString();
        SimpleCertificateReport simpleReport = reports.getSimpleReport();

        List<CertificateApprovalStatus> certificateApprovalStatusAtCertificateIssuance = simpleReport.getCertificateApprovalStatusAtCertificateIssuance();
        assertEquals(1, certificateApprovalStatusAtCertificateIssuance.size());
        assertEquals(CertificateApprovalStatusEnum.PID_PROVIDER, certificateApprovalStatusAtCertificateIssuance.get(0));
        assertEquals(0, simpleReport.getCertificateApprovalStatusErrorsAtIssuanceTime(certId, certificateApprovalStatusAtCertificateIssuance.get(0)).size());
        assertEquals(0, simpleReport.getCertificateApprovalStatusWarningsAtIssuanceTime(certId, certificateApprovalStatusAtCertificateIssuance.get(0)).size());
        assertEquals(0, simpleReport.getCertificateApprovalStatusInfoAtIssuanceTime(certId, certificateApprovalStatusAtCertificateIssuance.get(0)).size());

        List<CertificateApprovalStatus> certificateApprovalStatusAtValidationTime = simpleReport.getCertificateApprovalStatusAtValidationTime();
        assertEquals(1, certificateApprovalStatusAtValidationTime.size());
        assertEquals(CertificateApprovalStatusEnum.PID_PROVIDER, certificateApprovalStatusAtValidationTime.get(0));
        assertEquals(0, simpleReport.getCertificateApprovalStatusErrorsAtValidationTime(certId, certificateApprovalStatusAtValidationTime.get(0)).size());
        assertEquals(0, simpleReport.getCertificateApprovalStatusWarningsAtValidationTime(certId, certificateApprovalStatusAtValidationTime.get(0)).size());
        assertEquals(0, simpleReport.getCertificateApprovalStatusInfoAtValidationTime(certId, certificateApprovalStatusAtValidationTime.get(0)).size());

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<XmlListOfTrustedEntities> listsOfTrustedEntities = diagnosticData.getListsOfTrustedEntities();
        assertEquals(2, listsOfTrustedEntities.size());

        boolean loloteFound = false;
        boolean loteFound = false;
        for (XmlListOfTrustedEntities xmlListOfTrustedEntities : listsOfTrustedEntities) {
            if (xmlListOfTrustedEntities.getParent() != null) {
                loteFound = true;
            } else {
                loloteFound = true;
            }
        }
        assertTrue(loloteFound);
        assertTrue(loteFound);

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(pidCertificate.getDSSIdAsString());
        XmlCertificateApprovalStatusProcess certificateApprovalStatusProcess = xmlCertificate.getCertificateApprovalStatusProcess();

        boolean loloteCheckFound = false;
        boolean loteCheckFound = false;
        for (XmlConstraint constraint : certificateApprovalStatusProcess.getConstraint()) {
            if (MessageTag.CERT_USAGE_LOLOTE_ACCEPT.getId().equals(constraint.getName().getKey())) {
                loloteCheckFound = true;
            } else if (MessageTag.CERT_USAGE_LOTE_ACCEPT.getId().equals(constraint.getName().getKey())) {
                loteCheckFound = true;
            }
            assertEquals(XmlStatus.OK, constraint.getStatus());
        }
        assertTrue(loloteCheckFound);
        assertTrue(loteCheckFound);
    }

    private DSSDocument createLoLoTE() {
        signer = LOLOTE_SIGNER_CERTIFICATE;

        JsonObject root = new JsonObject();

        JsonObject lote = new JsonObject();
        root.put("LoTE", lote);

        JsonObject listAndSchemeInformation = new JsonObject();
        lote.put("ListAndSchemeInformation", listAndSchemeInformation);

        listAndSchemeInformation.put("LoTEVersionIdentifier", 1);
        listAndSchemeInformation.put("LoTESequenceNumber", 1);
        listAndSchemeInformation.put("LoTEType", EU_LIST_OF_LISTS_TYPE);

        List<JsonObject> schemeOperatorName = new ArrayList<>();
        schemeOperatorName.add(getMultiLangString("fr", "Commission Européenne"));
        schemeOperatorName.add(getMultiLangString("en", "European Commission"));
        listAndSchemeInformation.put("SchemeOperatorName", schemeOperatorName);

        JsonObject schemeOperatorAddress = new JsonObject();
        listAndSchemeInformation.put("SchemeOperatorAddress", schemeOperatorAddress);

        List<JsonObject> schemeOperatorPostalAddress = new ArrayList<>();
        schemeOperatorPostalAddress.add(getPostalAddress("fr", "12 Boulevard Sécurité", "Paris", "Île-de-France","75015", "ZZ"));
        schemeOperatorPostalAddress.add(getPostalAddress("en", "12 Security Boulevard", "Paris", "Ile-de-France","75015", "ZZ"));
        schemeOperatorAddress.put("SchemeOperatorPostalAddress", schemeOperatorPostalAddress);

        List<JsonObject> schemeOperatorElectronicAddress = new ArrayList<>();
        schemeOperatorElectronicAddress.add(getNonEmptyMultiLangURI("en", "mailto:mailto@schemeoperator.com"));
        schemeOperatorAddress.put("SchemeOperatorElectronicAddress", schemeOperatorElectronicAddress);

        List<JsonObject> schemeName = new ArrayList<>();
        schemeName.add(getMultiLangString("fr", "Liste de confiance zz"));
        schemeName.add(getMultiLangString("en", "ZZ Trusted List"));
        listAndSchemeInformation.put("SchemeName", schemeName);

        List<JsonObject> schemeInformationURI = new ArrayList<>();
        schemeInformationURI.add(getNonEmptyMultiLangURI("en", "https://example.org/scheme-info"));
        listAndSchemeInformation.put("SchemeInformationURI", schemeInformationURI);

        listAndSchemeInformation.put("StatusDeterminationApproach", EU_LIST_OF_LISTS_STATUS_DETERMINATION_APPROACH);

        List<JsonObject> schemeTypeCommunityRules = new ArrayList<>();
        schemeTypeCommunityRules.add(getNonEmptyMultiLangURI("en", EU_LIST_OF_LISTS_SCHEME_TYPE_COMMUNITY_RULES));
        listAndSchemeInformation.put("SchemeTypeCommunityRules", schemeTypeCommunityRules);

        listAndSchemeInformation.put("SchemeTerritory", "EU");

        List<JsonObject> policyOrLegalNotice = new ArrayList<>();
        JsonObject policyOrLegalNoticeEntry = new JsonObject();
        policyOrLegalNoticeEntry.put("LoTEPolicy", getNonEmptyMultiLangURI("en", "http://trust.tech.ec.europa.eu/lists/eudiw/legal-notice#EN"));
        policyOrLegalNotice.add(policyOrLegalNoticeEntry);
        listAndSchemeInformation.put("PolicyOrLegalNotice", policyOrLegalNotice);

        Calendar calendar = Calendar.getInstance();
        listAndSchemeInformation.put("ListIssueDateTime", DSSUtils.formatDateToRFC(calendar.getTime()));

        calendar.add(Calendar.MONTH, 6);
        listAndSchemeInformation.put("NextUpdate", DSSUtils.formatDateToRFC(calendar.getTime()));

        List<JsonObject> pointersToOtherLOTE = new ArrayList<>();
        listAndSchemeInformation.put("PointersToOtherLoTE", pointersToOtherLOTE);

        JsonObject selfLoTEPointer = new JsonObject();
        selfLoTEPointer.put("LoTELocation", LOLOTE_LOCATION_URL);

        List<JsonObject> serviceDigitalIdentities = new ArrayList<>();
        serviceDigitalIdentities.add(getServiceDigitalIdentity(getCertificate(LOLOTE_SIGNER_CERTIFICATE)));
        selfLoTEPointer.put("ServiceDigitalIdentities", serviceDigitalIdentities);

        List<JsonObject> loteQualifiers = new ArrayList<>();

        JsonObject loteQualifier = new JsonObject();
        loteQualifier.put("LoTEType", EU_LIST_OF_LISTS_TYPE);
        loteQualifier.put("SchemeOperatorName", schemeOperatorName);
        loteQualifier.put("SchemeTerritory", "EU");
        loteQualifier.put("SchemeTypeCommunityRules",schemeTypeCommunityRules);
        loteQualifier.put("MimeType", MimeTypeEnum.JSON.getMimeTypeString());
        loteQualifiers.add(loteQualifier);

        selfLoTEPointer.put("LoTEQualifiers", loteQualifiers);

        pointersToOtherLOTE.add(selfLoTEPointer);

        JsonObject otherLoTEPointer = new JsonObject();
        otherLoTEPointer.put("LoTELocation", LOTE_LOCATION_URL);

        serviceDigitalIdentities = new ArrayList<>();
        serviceDigitalIdentities.add(getServiceDigitalIdentity(getCertificate(LOTE_SIGNER_CERTIFICATE)));
        otherLoTEPointer.put("ServiceDigitalIdentities", serviceDigitalIdentities);

        loteQualifiers = new ArrayList<>();
        loteQualifier = new JsonObject();
        loteQualifier.put("LoTEType", PID_PROVIDERS_LIST_TYPE);

        List<JsonObject> schemeOperatorNameLoTE = new ArrayList<>();
        schemeOperatorNameLoTE.add(getMultiLangString("fr", "Agence Nationale de la Confiance Numérique"));
        schemeOperatorNameLoTE.add(getMultiLangString("en", "National Agency for Digital Trust"));
        loteQualifier.put("SchemeOperatorName", schemeOperatorNameLoTE);

        schemeTypeCommunityRules = new ArrayList<>();
        schemeTypeCommunityRules.add(getNonEmptyMultiLangURI("en", PID_LIST_SCHEME_TYPE_COMMUNITY_RULES));
        loteQualifier.put("SchemeTypeCommunityRules", schemeTypeCommunityRules);

        loteQualifier.put("SchemeTerritory", "EU");
        loteQualifier.put("MimeType", MimeTypeEnum.JSON.getMimeTypeString());
        loteQualifiers.add(loteQualifier);

        otherLoTEPointer.put("LoTEQualifiers", loteQualifiers);

        pointersToOtherLOTE.add(otherLoTEPointer);

        DSSDocument loteToSign = toDSSDocument(root);

        JAdESService service = new JAdESService(getOfflineCertificateVerifier());
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

        ToBeSigned dataToSign = service.getDataToSign(loteToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedLoTE = service.signDocument(loteToSign, signatureParameters, signatureValue);
        return signedLoTE;
    }

    private DSSDocument createLoTE() {
        signer = LOTE_SIGNER_CERTIFICATE;

        JsonObject root = new JsonObject();

        JsonObject lote = new JsonObject();
        root.put("LoTE", lote);

        JsonObject listAndSchemeInformation = new JsonObject();
        lote.put("ListAndSchemeInformation", listAndSchemeInformation);

        listAndSchemeInformation.put("LoTEVersionIdentifier", 1);
        listAndSchemeInformation.put("LoTESequenceNumber", 1);
        listAndSchemeInformation.put("LoTEType", PID_PROVIDERS_LIST_TYPE);

        List<JsonObject> schemeOperatorName = new ArrayList<>();
        schemeOperatorName.add(getMultiLangString("fr", "Agence Nationale de la Confiance Numérique"));
        schemeOperatorName.add(getMultiLangString("en", "National Agency for Digital Trust"));
        listAndSchemeInformation.put("SchemeOperatorName", schemeOperatorName);

        JsonObject schemeOperatorAddress = new JsonObject();
        listAndSchemeInformation.put("SchemeOperatorAddress", schemeOperatorAddress);

        List<JsonObject> schemeOperatorPostalAddress = new ArrayList<>();
        schemeOperatorPostalAddress.add(getPostalAddress("fr", "12 Boulevard Sécurité", "Paris", "Île-de-France","75015", "ZZ"));
        schemeOperatorPostalAddress.add(getPostalAddress("en", "12 Security Boulevard", "Paris", "Ile-de-France","75015", "ZZ"));
        schemeOperatorAddress.put("SchemeOperatorPostalAddress", schemeOperatorPostalAddress);

        List<JsonObject> schemeOperatorElectronicAddress = new ArrayList<>();
        schemeOperatorElectronicAddress.add(getNonEmptyMultiLangURI("en", "mailto:mailto@schemeoperator.com"));
        schemeOperatorAddress.put("SchemeOperatorElectronicAddress", schemeOperatorElectronicAddress);

        List<JsonObject> schemeName = new ArrayList<>();
        schemeName.add(getMultiLangString("fr", "Liste de confiance zz"));
        schemeName.add(getMultiLangString("en", "ZZ Trusted List"));
        listAndSchemeInformation.put("SchemeName", schemeName);

        List<JsonObject> schemeInformationURI = new ArrayList<>();
        schemeInformationURI.add(getNonEmptyMultiLangURI("en", "https://example.org/scheme-info"));
        listAndSchemeInformation.put("SchemeInformationURI", schemeInformationURI);

        listAndSchemeInformation.put("StatusDeterminationApproach", PID_LIST_STATUS_DETERMINATION_APPROACH);

        List<JsonObject> schemeTypeCommunityRules = new ArrayList<>();
        schemeTypeCommunityRules.add(getNonEmptyMultiLangURI("en", PID_LIST_SCHEME_TYPE_COMMUNITY_RULES));
        listAndSchemeInformation.put("SchemeTypeCommunityRules", schemeTypeCommunityRules);

        listAndSchemeInformation.put("SchemeTerritory", "EU");

        List<JsonObject> policyOrLegalNotice = new ArrayList<>();
        JsonObject policyOrLegalNoticeEntry = new JsonObject();
        policyOrLegalNoticeEntry.put("LoTEPolicy", getNonEmptyMultiLangURI("en", "http://trust.tech.ec.europa.eu/lists/eudiw/legal-notice#EN"));
        policyOrLegalNotice.add(policyOrLegalNoticeEntry);
        listAndSchemeInformation.put("PolicyOrLegalNotice", policyOrLegalNotice);

        Calendar calendar = Calendar.getInstance();
        listAndSchemeInformation.put("ListIssueDateTime", DSSUtils.formatDateToRFC(calendar.getTime()));

        calendar.add(Calendar.MONTH, 6);
        listAndSchemeInformation.put("NextUpdate", DSSUtils.formatDateToRFC(calendar.getTime()));

        List<JsonObject> trustedEntitiesList = new ArrayList<>();
        lote.put("TrustedEntitiesList", trustedEntitiesList);

        JsonObject trustedEntity = new JsonObject();
        trustedEntitiesList.add(trustedEntity);

        JsonObject trustedEntityInformation = new JsonObject();
        trustedEntity.put("TrustedEntityInformation", trustedEntityInformation);

        List<JsonObject> teName = new ArrayList<>();
        teName.add(getMultiLangString("en", "Agence Nationale des Titres Sécurisés"));
        trustedEntityInformation.put("TEName", teName);

        List<JsonObject> teTradeName = new ArrayList<>();
        teTradeName.add(getMultiLangString("en", "VATZZ-12345"));
        trustedEntityInformation.put("TETradeName", teTradeName);

        JsonObject teAddress = new JsonObject();
        trustedEntityInformation.put("TEAddress", teAddress);

        List<JsonObject> tePostalAddress = new ArrayList<>();
        tePostalAddress.add(getPostalAddress("en", "test", "test", "test", "3465", "ZZ"));
        teAddress.put("TEPostalAddress", tePostalAddress);

        List<JsonObject> teElectronicAddress = new ArrayList<>();
        teElectronicAddress.add(getNonEmptyMultiLangURI("en", "mailto:test@test.fr"));
        teElectronicAddress.add(getNonEmptyMultiLangURI("en", "tel:+337848346754"));
        teAddress.put("TEElectronicAddress", teElectronicAddress);

        List<JsonObject> teInformationURI = new ArrayList<>();
        teInformationURI.add(getNonEmptyMultiLangURI("en", "http://test.fr"));
        teInformationURI.add(getNonEmptyMultiLangURI("en", "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/ZZ"));
        trustedEntityInformation.put("TEInformationURI", teInformationURI);

        List<JsonObject> trustedEntityServices = new ArrayList<>();
        trustedEntity.put("TrustedEntityServices", trustedEntityServices);

        CertificateSource trustedCertificateSource = getTrustedCertificateSourceByPKIName(PKI_NAME);
        for (CertificateToken sdiCertificate : trustedCertificateSource.getCertificates()) {
            JsonObject trustedEntityService = new JsonObject();

            JsonObject serviceInformation = new JsonObject();
            trustedEntityService.put("ServiceInformation", serviceInformation);

            List<JsonObject> serviceName = new ArrayList<>();
            serviceName.add(getMultiLangString("en", DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, sdiCertificate.getSubject())));
            serviceInformation.put("ServiceName", serviceName);

            JsonObject serviceDigitalIdentity = getServiceDigitalIdentity(sdiCertificate);
            serviceInformation.put("ServiceDigitalIdentity", serviceDigitalIdentity);

            serviceInformation.put("ServiceTypeIdentifier", PID_SERVICE_TYPE_IDENTIFIER);

            trustedEntityServices.add(trustedEntityService);
        }

        DSSDocument loteToSign = toDSSDocument(root);

        JAdESService service = new JAdESService(getOfflineCertificateVerifier());
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

        ToBeSigned dataToSign = service.getDataToSign(loteToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedLoTE = service.signDocument(loteToSign, signatureParameters, signatureValue);
        return signedLoTE;
    }

    private JsonObject getServiceDigitalIdentity(CertificateToken... certificates) {
        JsonObject serviceDigitalIdentity = new JsonObject();

        List<JsonObject> x509Certificates = new ArrayList<>();
        serviceDigitalIdentity.put("X509Certificates", x509Certificates);

        for (CertificateToken certificateToken : certificates) {
            JsonObject x509Certificate = new JsonObject();
            x509Certificate.put("val", Utils.toBase64(certificateToken.getEncoded()));
            x509Certificates.add(x509Certificate);
        }

        return serviceDigitalIdentity;
    }

    private JsonObject getMultiLangString(String lang, String value) {
        JsonObject multiLangString = new JsonObject();
        multiLangString.put("lang", lang);
        multiLangString.put("value", value);
        return multiLangString;
    }

    private JsonObject getPostalAddress(String lang, String streetAddress, String locality, String stateOrProvince, String postalCode, String country) {
        JsonObject postalAddress = new JsonObject();
        postalAddress.put("lang", lang);
        postalAddress.put("StreetAddress", streetAddress);
        postalAddress.put("Locality", locality);
        postalAddress.put("StateOrProvince", stateOrProvince);
        postalAddress.put("PostalCode", postalCode);
        postalAddress.put("Country", country);
        return postalAddress;
    }

    private JsonObject getNonEmptyMultiLangURI(String lang, String uriValue) {
        JsonObject electronicAddress = new JsonObject();
        electronicAddress.put("lang", lang);
        electronicAddress.put("uriValue", uriValue);
        return electronicAddress;
    }

    private DSSDocument toDSSDocument(JsonObject jsonObject) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writeValueAsString(jsonObject);
            return new InMemoryDocument(json.getBytes());
        } catch (JsonProcessingException e) {
            fail(e);
            return null;
        }
    }

    @Override
    protected String getSigningAlias() {
        return signer;
    }

    @AfterEach
    void clean() throws IOException {
        cacheDirectory.mkdirs();
        Files.walk(cacheDirectory.toPath()).map(Path::toFile).forEach(File::delete);
    }

}
