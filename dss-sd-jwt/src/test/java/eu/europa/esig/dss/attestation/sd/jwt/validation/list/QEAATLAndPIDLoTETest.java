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
package eu.europa.esig.dss.attestation.sd.jwt.validation.list;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
import eu.europa.esig.dss.attestation.sd.jwt.MockDataLoader;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.EAACategory;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.tsl.TrustedListV6SignatureParametersBuilder;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.trustedlist.jaxb.tsl.ElectronicAddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionsListType;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.NextUpdateType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.PolicyOrLegalnoticeType;
import eu.europa.esig.trustedlist.jaxb.tsl.PostalAddressListType;
import eu.europa.esig.trustedlist.jaxb.tsl.PostalAddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServicesListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import jakarta.xml.bind.JAXBElement;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class QEAATLAndPIDLoTETest extends PKIFactoryAccess {

    private static final String PKI_NAME = "qeaa-and-pid-providers";

    private static final String TL_LOCATION_URL = "https://test.test/tl";

    private static final String TRUST_SERVICE_IDENTIFIER_CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
    private static final String TRUST_SERVICE_IDENTIFIER_PKC = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC";
    private static final String TRUST_SERVICE_IDENTIFIER_EAA_Q = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q";
    private static final String TRUST_SERVICE_IDENTIFIER_EAA_PUBEAA = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA";
    private static final String TRUST_SERVICE_IDENTIFIER_EAA = "http://uri.etsi.org/TrstSvc/Svctype/EAA";

    private static final String TRUST_SERVICE_STATUS_GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

    private static final Map<String, String> TRUST_SERVICE_CERT_CORRESPONDANCE_MAP = new HashMap<>();

    private static final String LoTE_LOCATION_URL = "https://test.test/pid-providers-list";

    private static final String PID_PROVIDERS_LIST_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";
    private static final String PID_SERVICE_TYPE_IDENTIFIER = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    private static final String PID_LIST_STATUS_DETERMINATION_APPROACH = "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU";
    private static final String PID_LIST_SCHEME_TYPE_COMMUNITY_RULES = "http://uri.etsi.org/19602/PIDProviders/schemerules/EU";

    private static Map<String, DSSDocument> urlMap;
    private static FileCacheDataLoader onlineFileLoader;
    private static File cacheDirectory;

    private static final String TL_SIGNER_CERTIFICATE = "ZZ-TL-signer";
    private CertificateToken tlSignerCertificate;

    private static final String LOTE_SIGNER_CERTIFICATE = "LoTE-Signer";
    private CertificateToken loteSignerCertificate;

    private TrustedListsCertificateSource trustedListsCertificateSource;
    private TrustedEntitiesCertificateSource trustedEntitiesCertificateSource;

    private String signer;

    @BeforeEach
    public void init() {
        urlMap = new HashMap<>();

        cacheDirectory = new File("target/cache");

        onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);

        tlSignerCertificate = getCertificate(TL_SIGNER_CERTIFICATE);
        loteSignerCertificate = getCertificate(LOTE_SIGNER_CERTIFICATE);

        TRUST_SERVICE_CERT_CORRESPONDANCE_MAP.put("QEAA", TRUST_SERVICE_IDENTIFIER_EAA_Q);
        TRUST_SERVICE_CERT_CORRESPONDANCE_MAP.put("PubEAA", TRUST_SERVICE_IDENTIFIER_EAA_PUBEAA);
        TRUST_SERVICE_CERT_CORRESPONDANCE_MAP.put("EAA", TRUST_SERVICE_IDENTIFIER_EAA);
        TRUST_SERVICE_CERT_CORRESPONDANCE_MAP.put("CAQC", TRUST_SERVICE_IDENTIFIER_CA_QC);
        TRUST_SERVICE_CERT_CORRESPONDANCE_MAP.put("PKC", TRUST_SERVICE_IDENTIFIER_PKC);
    }

    static Stream<Arguments> data() throws Exception {
        final List<Arguments> data = new ArrayList<>();

        data.add(Arguments.of("Test-QEAA-PID", Arrays.asList(AttestationQualification.QEAA, AttestationQualification.PID)));
        data.add(Arguments.of("Test-QEAA", Collections.singletonList(AttestationQualification.QEAA)));
        data.add(Arguments.of("Test-EAA-PID", Arrays.asList(AttestationQualification.EAA, AttestationQualification.PID)));
        data.add(Arguments.of("Test-QC-PID", Arrays.asList(AttestationQualification.EAA, AttestationQualification.PID)));
        data.add(Arguments.of("Test-QC-CERT", Collections.singletonList(AttestationQualification.EAA)));
        data.add(Arguments.of("Test-QC-PubEAA", Collections.singletonList(AttestationQualification.PUBEAA)));
        data.add(Arguments.of("Test-QC-PubEAA-PID", Arrays.asList(AttestationQualification.PUBEAA, AttestationQualification.PID)));
        data.add(Arguments.of("Test-Non-Qualified-CERT", Collections.singletonList(AttestationQualification.EAA)));
        data.add(Arguments.of("Test-PKC-EAA-PID", Arrays.asList(AttestationQualification.EAA, AttestationQualification.PID)));
        data.add(Arguments.of("Test-PKC-EAA", Collections.singletonList(AttestationQualification.EAA)));
        data.add(Arguments.of("Test-PKC-PID", Arrays.asList(AttestationQualification.EAA, AttestationQualification.PID)));
        data.add(Arguments.of("Test-PKC-CERT", Collections.singletonList(AttestationQualification.EAA)));
        data.add(Arguments.of("Test-PKC-PubEAA", Collections.singletonList(AttestationQualification.EAA)));
        data.add(Arguments.of("Test-PKC-PubEAA-PID", Arrays.asList(AttestationQualification.EAA, AttestationQualification.PID)));
        data.add(Arguments.of("Test-not-trusted-EAA-CERT", Collections.singletonList(AttestationQualification.NA)));

        return data.stream();
    }

    @ParameterizedTest(name = "Attestation Qualification Test : {0}")
    @MethodSource("data")
    void test(String signerName, Collection<AttestationQualification> expectedQualification) {
        signer = signerName;
        DSSDocument attestationPresentation = createAttestationPresentation();

        SignedDocumentValidator validator = DefaultAttestationDocumentValidator.fromDocument(attestationPresentation);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setTrustedCertSources(getTrustedListSource(), getTrustedEntitiesSource());
        validator.setCertificateVerifier(certificateVerifier);

        Reports reports = validator.validateDocument();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(expectedQualification, simpleReport.getAttestationQualifications(simpleReport.getFirstAttestationId()));
    }

    private TrustedListsCertificateSource getTrustedListSource() {
        if (trustedListsCertificateSource == null) {
            trustedListsCertificateSource = new TrustedListsCertificateSource();

            TLValidationJob validationJob = new TLValidationJob();
            validationJob.setTrustedListCertificateSource(trustedListsCertificateSource);

            signer = TL_SIGNER_CERTIFICATE;
            DSSDocument trustedList = createTL();

            urlMap.put(TL_LOCATION_URL, trustedList);
            validationJob.setOnlineDataLoader(onlineFileLoader);

            TLSource tlSource = new TLSource();
            tlSource.setUrl(TL_LOCATION_URL);
            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
            trustedCertificateSource.addCertificate(tlSignerCertificate);
            tlSource.setCertificateSource(trustedCertificateSource);
            validationJob.setTrustedListSources(tlSource);

            validationJob.onlineRefresh();

            TLValidationJobSummary summary = validationJob.getSummary();
            assertEquals(13, trustedListsCertificateSource.getNumberOfCertificates());
            assertEquals(Indication.TOTAL_PASSED, summary.getOtherTLInfos().get(0).getValidationCacheInfo().getIndication());
        }
        return trustedListsCertificateSource;
    }

    private TrustedEntitiesCertificateSource getTrustedEntitiesSource() {
        if (trustedEntitiesCertificateSource == null) {
            trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();

            LoTEValidationJob validationJob = new LoTEValidationJob();
            validationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);

            signer = LOTE_SIGNER_CERTIFICATE;
            DSSDocument pidProvidersLoTE = createLoTE();

            urlMap.put(LoTE_LOCATION_URL, pidProvidersLoTE);
            validationJob.setOnlineDataLoader(onlineFileLoader);

            LoTESource loteSource = new LoTESource();
            loteSource.setUrl(LoTE_LOCATION_URL);
            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
            trustedCertificateSource.addCertificate(loteSignerCertificate);
            loteSource.setCertificateSource(trustedCertificateSource);
            validationJob.setLoTESources(loteSource);

            validationJob.onlineRefresh();

            LoTEValidationJobSummary summary = validationJob.getSummary();
            assertEquals(1, trustedCertificateSource.getNumberOfCertificates());
            assertEquals(Indication.TOTAL_PASSED, summary.getOtherLoTEInfos().get(0).getValidationCacheInfo().getIndication());
        }
        return trustedEntitiesCertificateSource;
    }

    private DSSDocument createAttestationPresentation() {
        String commonName = DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, getSigningCert().getSubject());

        String category = null;
        String vct;
        if (commonName.contains("QEAA")) {
            category = EAACategory.EU_QEAA.getUrn();
        } else if (commonName.contains("PubEAA")) {
            category = EAACategory.EU_PUBEAA.getUrn();
        }
        if (commonName.contains("PID")) {
            vct = "urn:eudi:pid:1";
        } else {
            vct = "urn:eudi:attestation:1";
        }

        String payload = "{\n" +
                "  \"iss\": \"https://issuer.example.com\",\n" +
                "  \"iat\": 1683000000,\n" +
                "  \"nbf\": 1683000000,\n" +
                "  \"exp\": 1883000000,\n" +
                "  \"sub\": \"user_42\",\n" +
                (category != null ? ("  \"category\": \"" + category + "\",\n") : "") +
                "  \"vct\": \"" + vct + "\",\n" +
                "  \"vct#integrity\": \"sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=\",\n" +
                "  \"nationalities\": [\n" +
                "    \"US\"\n" +
                "  ],\n" +
                "  \"cnf\": {\n" +
                "    \"jwk\": {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"crv\": \"P-256\",\n" +
                "      \"x\": \"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\",\n" +
                "      \"y\": \"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"family_name\": \"Doe\",\n" +
                "  \"address\": {\n" +
                "    \"street_address\": \"123 Main St\",\n" +
                "    \"locality\": \"Anytown\",\n" +
                "    \"region\": \"Anystate\",\n" +
                "    \"country\": \"US\"\n" +
                "  },\n" +
                "  \"given_name\": \"John\",\n" +
                "  \"shortLived\": null,\n" +
                "}";
        DSSDocument originalDocument = new InMemoryDocument(payload.getBytes());

        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setX509Url("http://nowina.lu/pki-factory/" + commonName);
        signatureParameters.bLevel().setTrustAnchorBPPolicy(false); // TODO : revert after DSS-3859 fix

        JAdESService service = new JAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(originalDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(originalDocument, signatureParameters, signatureValue);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Utils.write(DSSUtils.toByteArray(signedDocument), baos);
            baos.write('~');
            return new InMemoryDocument(baos.toByteArray(), "simple-sd-jwt.jwt");

        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private DSSDocument createTL() {
        TrustStatusListType trustedList = new TrustStatusListType();
        trustedList.setTSLTag("http://uri.etsi.org/19612/TSLTag");

        TSLSchemeInformationType schemeInformation = new TSLSchemeInformationType();
        trustedList.setSchemeInformation(schemeInformation);

        schemeInformation.setTSLVersionIdentifier(BigInteger.valueOf(6));
        schemeInformation.setTSLSequenceNumber(BigInteger.ONE);
        schemeInformation.setTSLType("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric");

        schemeInformation.setSchemeOperatorName(getNamesType(
                getLangString("fr", "Agence Nationale de la Confiance Numérique"),
                getLangString("en", "National Agency for Digital Trust")
        ));

        schemeInformation.setSchemeOperatorAddress(getAddressType(Arrays.asList(
                getPostalAddress("fr", "12 Boulevard Sécurité", "Paris", "Île-de-France","75015", "ZZ"),
                getPostalAddress("en", "12 Security Boulevard", "Paris", "Ile-de-France","75015", "ZZ")
        ), getElectronicAddress(getLangURI("en", "mailto:mailto@schemeoperator.com"))));

        schemeInformation.setSchemeName(getNamesType(
                getLangString("fr", "Liste de confiance zz"),
                getLangString("en", "ZZ Trusted List")
        ));

        schemeInformation.setSchemeInformationURI(getLangUriList(getLangURI("en", "https://example.org/scheme-info")));
        schemeInformation.setStatusDeterminationApproach("http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU");
        schemeInformation.setSchemeTypeCommunityRules(getLangUriList(getLangURI("en", "http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU")));
        schemeInformation.setSchemeTerritory("ZZ");

        schemeInformation.setHistoricalInformationPeriod(BigInteger.valueOf(65535));

        PolicyOrLegalnoticeType policyOrLegalnoticeType = new PolicyOrLegalnoticeType();
        policyOrLegalnoticeType.getTSLPolicy().add(getLangURI("en", "http://trust.tech.ec.europa.eu/lists/eudiw/legal-notice#EN"));
        schemeInformation.setPolicyOrLegalNotice(policyOrLegalnoticeType);

        schemeInformation.setListIssueDateTime(toXMLGregorianCalendar(new Date()));

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, 6);

        NextUpdateType nextUpdateType = new NextUpdateType();
        nextUpdateType.setDateTime(toXMLGregorianCalendar(calendar.getTime()));
        schemeInformation.setNextUpdate(nextUpdateType);

        TrustServiceProviderListType trustServiceProviderListType = new TrustServiceProviderListType();
        trustedList.setTrustServiceProviderList(trustServiceProviderListType);

        TSPType tspType = new TSPType();
        trustServiceProviderListType.getTrustServiceProvider().add(tspType);

        TSPInformationType tspInformationType = new TSPInformationType();
        tspInformationType.setTSPName(getNamesType(getLangString("en", "Agence Nationale des Titres Sécurisés")));
        tspInformationType.setTSPTradeName(getNamesType(getLangString("en", "VATZZ-12345")));
        tspInformationType.setTSPAddress(getAddressType(
                Collections.singleton(getPostalAddress("en", "test", "test", "test", "3465", "ZZ")),
                getElectronicAddress(getLangURI("en", "mailto:test@test.fr"), getLangURI("en", "tel:+337848346754"))
        ));
        tspInformationType.setTSPInformationURI(getLangUriList(
                getLangURI("en", "http://test.fr"),
                getLangURI("en", "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/ZZ")
        ));
        tspType.setTSPInformation(tspInformationType);

        TSPServicesListType tspServicesListType = new TSPServicesListType();
        tspType.setTSPServices(tspServicesListType);

        CertificateSource trustedCertificateSource = getTrustedCertificateSourceByPKIName(PKI_NAME);
        for (CertificateToken sdiCertificate : trustedCertificateSource.getCertificates()) {
            for (Map.Entry<String, String> entry : TRUST_SERVICE_CERT_CORRESPONDANCE_MAP.entrySet()) {
                String commonNameKey = entry.getKey();
                String sti = entry.getValue();

                String commonName = DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, sdiCertificate.getSubject());
                if (commonName == null || !commonName.contains(commonNameKey)) {
                    continue;
                }

                TSPServiceType tspServiceType = new TSPServiceType();

                TSPServiceInformationType serviceInformation = new TSPServiceInformationType();
                tspServiceType.setServiceInformation(serviceInformation);

                serviceInformation.setServiceName(getNamesType(getLangString("en", DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, sdiCertificate.getSubject()))));

                DigitalIdentityListType digitalIdentities = new DigitalIdentityListType();
                DigitalIdentityType digitalIdentityType = new DigitalIdentityType();
                digitalIdentityType.setX509Certificate(sdiCertificate.getEncoded());
                digitalIdentities.getDigitalId().add(digitalIdentityType);
                serviceInformation.setServiceDigitalIdentity(digitalIdentities);
                serviceInformation.setServiceTypeIdentifier(sti);

                if ("CAQC".equals(commonNameKey) || "PKC".equals(commonNameKey)) {

                    ExtensionsListType extensionsListType = new ExtensionsListType();
                    AdditionalServiceInformationType aiaForESig = new AdditionalServiceInformationType();
                    aiaForESig.setURI(getLangURI("en", "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"));

                    JAXBElement<AdditionalServiceInformationType> jaxbForESig = new JAXBElement<>(
                            new QName("http://uri.etsi.org/02231/v2#", "AdditionalServiceInformation"), AdditionalServiceInformationType.class, aiaForESig);

                    ExtensionType extForESig = new ExtensionType();
                    extForESig.getContent().add(jaxbForESig);
                    extForESig.setCritical(true);

                    extensionsListType.getExtension().add(extForESig);
                    serviceInformation.setServiceInformationExtensions(extensionsListType);

                }

                serviceInformation.setServiceStatus(TRUST_SERVICE_STATUS_GRANTED);
                serviceInformation.setStatusStartingTime(toXMLGregorianCalendar(sdiCertificate.getNotBefore()));

                tspServicesListType.getTSPService().add(tspServiceType);
            }
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            TrustedListFacade.newFacade().marshall(trustedList, baos);

            DSSDocument tlToSign = new InMemoryDocument(baos.toByteArray(), "LoTSP.xml");

            XAdESService service = new XAdESService(getOfflineCertificateVerifier());

            XAdESSignatureParameters signatureParameters = new TrustedListV6SignatureParametersBuilder(getSigningCert(), tlToSign).build();

            ToBeSigned dataToSign = service.getDataToSign(tlToSign, signatureParameters);
            SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
            DSSDocument signedTL = service.signDocument(tlToSign, signatureParameters, signatureValue);
            return signedTL;

        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private AddressType getAddressType(Collection<PostalAddressType> postalAddresses, ElectronicAddressType electronicAddress) {
        AddressType addressType = new AddressType();
        if (Utils.isCollectionNotEmpty(postalAddresses)) {
            PostalAddressListType postalAddressListType = new PostalAddressListType();
            postalAddressListType.getPostalAddress().addAll(postalAddresses);
            addressType.setPostalAddresses(postalAddressListType);
        }
        addressType.setElectronicAddress(electronicAddress);
        return addressType;
    }

    private PostalAddressType getPostalAddress(String lang, String street, String locality, String state, String postcode, String countryCode) {
        PostalAddressType postalAddress = new PostalAddressType();
        postalAddress.setLang(lang);
        postalAddress.setStreetAddress(street);
        postalAddress.setLocality(locality);
        postalAddress.setStateOrProvince(state);
        postalAddress.setPostalCode(postcode);
        postalAddress.setCountryName(countryCode);
        return postalAddress;
    }

    private ElectronicAddressType getElectronicAddress(NonEmptyMultiLangURIType... addresses) {
        ElectronicAddressType electronicAddress = new ElectronicAddressType();
        electronicAddress.getURI().addAll(Arrays.asList(addresses));
        return electronicAddress;
    }

    private NonEmptyMultiLangURIListType getLangUriList(NonEmptyMultiLangURIType... langUris) {
        NonEmptyMultiLangURIListType langURIListType = new NonEmptyMultiLangURIListType();
        langURIListType.getURI().addAll(Arrays.asList(langUris));
        return langURIListType;
    }

    private NonEmptyMultiLangURIType getLangURI(String lang, String uri) {
        NonEmptyMultiLangURIType uriType = new NonEmptyMultiLangURIType();
        uriType.setLang(lang);
        uriType.setValue(uri);
        return uriType;
    }

    private InternationalNamesType getNamesType(MultiLangNormStringType... strings) {
        InternationalNamesType namesType = new InternationalNamesType();
        namesType.getName().addAll(Arrays.asList(strings));
        return namesType;
    }

    private MultiLangNormStringType getLangString(String lang, String value) {
        MultiLangNormStringType stringType = new MultiLangNormStringType();
        stringType.setLang(lang);
        stringType.setValue(value);
        return stringType;
    }

    private XMLGregorianCalendar toXMLGregorianCalendar(Date date) {
        try {
            GregorianCalendar calendar = new GregorianCalendar();
            calendar.setTime(date);
            return DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);
        } catch (DatatypeConfigurationException e) {
            fail(e);
            return null;
        }
    }



    private DSSDocument createLoTE() {
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
        schemeOperatorPostalAddress.add(getJsonPostalAddress("fr", "12 Boulevard Sécurité", "Paris", "Île-de-France","75015", "ZZ"));
        schemeOperatorPostalAddress.add(getJsonPostalAddress("en", "12 Security Boulevard", "Paris", "Ile-de-France","75015", "ZZ"));
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
        tePostalAddress.add(getJsonPostalAddress("en", "test", "test", "test", "3465", "ZZ"));
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
            String commonName = DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, sdiCertificate.getSubject());
            if (commonName == null || !commonName.contains("PID")) {
                continue;
            }

            JsonObject trustedEntityService = new JsonObject();

            JsonObject serviceInformation = new JsonObject();
            trustedEntityService.put("ServiceInformation", serviceInformation);

            List<JsonObject> serviceName = new ArrayList<>();
            serviceName.add(getMultiLangString("en", DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, sdiCertificate.getSubject())));
            serviceInformation.put("ServiceName", serviceName);

            JsonObject serviceDigitalIdentity = new JsonObject();
            serviceInformation.put("ServiceDigitalIdentity", serviceDigitalIdentity);

            List<JsonObject> x509Certificates = new ArrayList<>();
            serviceDigitalIdentity.put("X509Certificates", x509Certificates);

            JsonObject x509Certificate = new JsonObject();
            x509Certificate.put("val", Utils.toBase64(sdiCertificate.getEncoded()));
            x509Certificates.add(x509Certificate);

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

    private JsonObject getMultiLangString(String lang, String value) {
        JsonObject multiLangString = new JsonObject();
        multiLangString.put("lang", lang);
        multiLangString.put("value", value);
        return multiLangString;
    }

    private JsonObject getJsonPostalAddress(String lang, String streetAddress, String locality, String stateOrProvince, String postalCode, String country) {
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

}
