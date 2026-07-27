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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class PIDLoTETest extends PKIFactoryAccess {

    private static final String PKI_NAME = "pid-providers";

    private static final String LoTE_LOCATION_URL = "https://test.test/pid-providers-list";

    private static final String PID_PROVIDERS_LIST_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";
    private static final String PID_SERVICE_TYPE_IDENTIFIER = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    private static final String PID_LIST_STATUS_DETERMINATION_APPROACH = "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU";
    private static final String PID_LIST_SCHEME_TYPE_COMMUNITY_RULES = "http://uri.etsi.org/19602/PIDProviders/schemerules/EU";

    private static Map<String, DSSDocument> urlMap;
    private static FileCacheDataLoader onlineFileLoader;
    private static File cacheDirectory;

    private static final String LOTE_SIGNER_CERTIFICATE = "LoTE-Signer";
    private CertificateToken loteSignerCertificate;

    private TrustedEntitiesCertificateSource trustedCertificateSource;

    private String signer;

    @BeforeEach
    public void init() {
        urlMap = new HashMap<>();

        cacheDirectory = new File("target/cache");

        onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);

        loteSignerCertificate = getCertificate(LOTE_SIGNER_CERTIFICATE);
    }

    static Stream<Arguments> data() {
        final List<Arguments> data = new ArrayList<>();
        data.add(Arguments.of("Test-PID", AttestationQualification.PID));
        data.add(Arguments.of("Test-not-trusted-EAA-CERT", AttestationQualification.NA));
        return data.stream();
    }

    @ParameterizedTest(name = "Attestation Qualification Test : {0}")
    @MethodSource("data")
    void test(String signerName, AttestationQualification expectedQualification) {
        signer = signerName;
        DSSDocument attestationPresentation = createAttestationPresentation();

        SignedDocumentValidator validator = DefaultAttestationDocumentValidator.fromDocument(attestationPresentation);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setTrustedCertSources(getTrustedSource());
        validator.setCertificateVerifier(certificateVerifier);

        Reports reports = validator.validateDocument();

        SimpleReport simpleReport = reports.getSimpleReport();

        AttestationQualification attestationQualification = simpleReport.getAttestationQualification(simpleReport.getFirstAttestationId());
        assertEquals(expectedQualification, attestationQualification);
        assertEquals(1, simpleReport.getAttestationQualifications(simpleReport.getFirstAttestationId()).size());
    }

    private TrustedEntitiesCertificateSource getTrustedSource() {
        if (trustedCertificateSource == null) {
            trustedCertificateSource = new TrustedEntitiesCertificateSource();

            LoTEValidationJob validationJob = new LoTEValidationJob();
            validationJob.setTrustedEntitiesCertificateSource(trustedCertificateSource);

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
        return trustedCertificateSource;
    }

    private DSSDocument createAttestationPresentation() {
        String commonName = DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, getSigningCert().getSubject());

        String payload = "{\n" +
                "  \"iss\": \"https://issuer.example.com\",\n" +
                "  \"iat\": 1683000000,\n" +
                "  \"nbf\": 1683000000,\n" +
                "  \"exp\": 1883000000,\n" +
                "  \"sub\": \"user_42\",\n" +
                "  \"vct\": \"urn:eudi:pid:1\",\n" +
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
                "}";
        DSSDocument originalDocument = new InMemoryDocument(payload.getBytes());

        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setX509Url("http://nowina.lu/pki-factory/" + commonName);

        JAdESService service = new JAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(originalDocument, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(originalDocument, signatureParameters, signatureValue);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Utils.write(DSSUtils.toByteArray(signedDocument), baos);
            baos.write('~');
            return new InMemoryDocument(baos.toByteArray(), "simple-pid.jwt");

        } catch (Exception e) {
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

}
