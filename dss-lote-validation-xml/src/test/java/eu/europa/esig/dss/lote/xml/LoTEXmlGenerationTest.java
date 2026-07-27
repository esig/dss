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
package eu.europa.esig.dss.lote.xml;

import eu.europa.esig.dss.enumerations.CertificateApprovalStatus;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatusEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.lote.job.LoTEValidationJob;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.lote.TrustedEntitiesCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.lote.jaxb.AddressType;
import eu.europa.esig.lote.jaxb.DigitalIdentityListType;
import eu.europa.esig.lote.jaxb.DigitalIdentityType;
import eu.europa.esig.lote.jaxb.ElectronicAddressType;
import eu.europa.esig.lote.jaxb.InternationalNamesType;
import eu.europa.esig.lote.jaxb.ListOfTrustedEntitiesType;
import eu.europa.esig.lote.jaxb.LoTEListAndSchemeInformationType;
import eu.europa.esig.lote.jaxb.MultiLangNormStringType;
import eu.europa.esig.lote.jaxb.NextUpdateType;
import eu.europa.esig.lote.jaxb.NonEmptyMultiLangURIListType;
import eu.europa.esig.lote.jaxb.NonEmptyMultiLangURIType;
import eu.europa.esig.lote.jaxb.PolicyOrLegalnoticeType;
import eu.europa.esig.lote.jaxb.PostalAddressListType;
import eu.europa.esig.lote.jaxb.PostalAddressType;
import eu.europa.esig.lote.jaxb.TEServiceInformationType;
import eu.europa.esig.lote.jaxb.TEType;
import eu.europa.esig.lote.jaxb.TrustedEntitiesListType;
import eu.europa.esig.lote.jaxb.TrustedEntityInformationType;
import eu.europa.esig.lote.jaxb.TrustedEntityServiceType;
import eu.europa.esig.lote.jaxb.TrustedEntityServicesListType;
import eu.europa.esig.lote.xml.LOTEFacade;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class LoTEXmlGenerationTest extends PKIFactoryAccess {

    private static final String PKI_NAME = "pub-eaa-providers";

    private static final String LOTE_LOCATION_URL = "https://test.test/lote";

    private static final String PUB_EAA_SERVICE_TYPE_IDENTIFIER = "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance";
    private static final String PUB_EAA_SERVICE_CURRENT_STATUS = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified";

    private static Map<String, DSSDocument> urlMap;
    private static FileCacheDataLoader onlineFileLoader;
    private static File cacheDirectory;

    private static final String PUB_EAA_CERTIFICATE = "Test-Pub-EAA";
    private CertificateToken pubEaaCertificate;

    private static final String LOTE_SIGNER_CERTIFICATE = "LoTE-Signer";
    private CertificateToken loteSignerCertificate;

    private String signer = LOTE_SIGNER_CERTIFICATE;

    @BeforeEach
    public void init() {
        urlMap = new HashMap<>();

        cacheDirectory = new File("target/cache");

        onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
        onlineFileLoader.setFileCacheDirectory(cacheDirectory);

        loteSignerCertificate = getCertificate(LOTE_SIGNER_CERTIFICATE);
        pubEaaCertificate = getCertificate(PUB_EAA_CERTIFICATE);
    }

    @Test
    void test() throws Exception {
        DSSDocument loTE = createLoTE();

        TrustedEntitiesCertificateSource trustedEntitiesCertificateSource = new TrustedEntitiesCertificateSource();

        LoTEValidationJob validationJob = new LoTEValidationJob();
        validationJob.setTrustedEntitiesCertificateSource(trustedEntitiesCertificateSource);

        urlMap.put(LOTE_LOCATION_URL, loTE);
        validationJob.setOnlineDataLoader(onlineFileLoader);

        LoTESource loTESource = new LoTESource();
        loTESource.setUrl(LOTE_LOCATION_URL);
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(loteSignerCertificate);
        loTESource.setCertificateSource(trustedCertificateSource);
        validationJob.setLoTESources(loTESource);

        validationJob.onlineRefresh();

        LoTEValidationJobSummary summary = validationJob.getSummary();
        assertEquals(1, trustedEntitiesCertificateSource.getNumberOfCertificates());
        assertEquals(Indication.TOTAL_PASSED, summary.getOtherLoTEInfos().get(0).getValidationCacheInfo().getIndication());

        assertEquals(1, trustedEntitiesCertificateSource.getCertificates().size());

        CertificateValidator validator = CertificateValidator.fromCertificate(pubEaaCertificate);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setTrustedCertSources(trustedEntitiesCertificateSource);
        validator.setCertificateVerifier(certificateVerifier);

        CertificateReports reports = validator.validate();

        String certId = pubEaaCertificate.getDSSIdAsString();
        SimpleCertificateReport simpleReport = reports.getSimpleReport();

        List<CertificateApprovalStatus> certificateApprovalStatusAtCertificateIssuance = simpleReport.getCertificateApprovalStatusAtCertificateIssuance();
        assertEquals(1, certificateApprovalStatusAtCertificateIssuance.size());
        assertEquals(CertificateApprovalStatusEnum.NOTIFIED_CERT_FOR_PUB_EAA_ISSUANCE, certificateApprovalStatusAtCertificateIssuance.get(0));
        assertEquals(0, simpleReport.getCertificateApprovalStatusErrorsAtIssuanceTime(certId, certificateApprovalStatusAtCertificateIssuance.get(0)).size());
        assertEquals(0, simpleReport.getCertificateApprovalStatusWarningsAtIssuanceTime(certId, certificateApprovalStatusAtCertificateIssuance.get(0)).size());
        assertEquals(0, simpleReport.getCertificateApprovalStatusInfoAtIssuanceTime(certId, certificateApprovalStatusAtCertificateIssuance.get(0)).size());

        List<CertificateApprovalStatus> certificateApprovalStatusAtValidationTime = simpleReport.getCertificateApprovalStatusAtValidationTime();
        assertEquals(1, certificateApprovalStatusAtValidationTime.size());
        assertEquals(CertificateApprovalStatusEnum.NOTIFIED_CERT_FOR_PUB_EAA_ISSUANCE, certificateApprovalStatusAtValidationTime.get(0));
        assertEquals(0, simpleReport.getCertificateApprovalStatusErrorsAtValidationTime(certId, certificateApprovalStatusAtValidationTime.get(0)).size());
        assertEquals(0, simpleReport.getCertificateApprovalStatusWarningsAtValidationTime(certId, certificateApprovalStatusAtValidationTime.get(0)).size());
        assertEquals(0, simpleReport.getCertificateApprovalStatusInfoAtValidationTime(certId, certificateApprovalStatusAtValidationTime.get(0)).size());

    }

    private DSSDocument createLoTE() {
        ListOfTrustedEntitiesType lote = new ListOfTrustedEntitiesType();
        lote.setLOTETag("http://uri.etsi.org/019602/tag#");

        LoTEListAndSchemeInformationType listAndSchemeInformation = new LoTEListAndSchemeInformationType();
        lote.setListAndSchemeInformation(listAndSchemeInformation);

        listAndSchemeInformation.setLoTEVersionIdentifier(BigInteger.ONE);
        listAndSchemeInformation.setLoTESequenceNumber(BigInteger.ONE);
        listAndSchemeInformation.setLoTEType("http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList");

        listAndSchemeInformation.setSchemeOperatorName(getNamesType(
                getLangString("fr", "Agence Nationale de la Confiance Numérique"),
                getLangString("en", "National Agency for Digital Trust")
        ));

        listAndSchemeInformation.setSchemeOperatorAddress(getAddressType(Arrays.asList(
                getPostalAddress("fr", "12 Boulevard Sécurité", "Paris", "Île-de-France","75015", "ZZ"),
                getPostalAddress("en", "12 Security Boulevard", "Paris", "Ile-de-France","75015", "ZZ")
        ), getElectronicAddress(getLangURI("en", "mailto:mailto@schemeoperator.com"))));

        listAndSchemeInformation.setSchemeName(getNamesType(
                getLangString("fr", "Liste de confiance zz"),
                getLangString("en", "ZZ Trusted List")
        ));

        listAndSchemeInformation.setSchemeInformationURI(getLangUriList(getLangURI("en", "https://example.org/scheme-info")));
        listAndSchemeInformation.setStatusDeterminationApproach("http://uri.etsi.org/19602/PubEAAProvidersList/StatusDetn/EU");
        listAndSchemeInformation.setSchemeTypeCommunityRules(getLangUriList(getLangURI("en", "http://uri.etsi.org/19602/PubEAAProvidersList/schemerules/EU")));
        listAndSchemeInformation.setSchemeTerritory("EU");

        listAndSchemeInformation.setHistoricalInformationPeriod(BigInteger.valueOf(65535));

        PolicyOrLegalnoticeType policyOrLegalnoticeType = new PolicyOrLegalnoticeType();
        policyOrLegalnoticeType.getLoTEPolicy().add(getLangURI("en", "http://trust.tech.ec.europa.eu/lists/eudiw/legal-notice#EN"));
        listAndSchemeInformation.setPolicyOrLegalNotice(policyOrLegalnoticeType);

        listAndSchemeInformation.setListIssueDateTime(toXMLGregorianCalendar(new Date()));

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, 6);

        NextUpdateType nextUpdateType = new NextUpdateType();
        nextUpdateType.setDateTime(toXMLGregorianCalendar(calendar.getTime()));
        listAndSchemeInformation.setNextUpdate(nextUpdateType);

        TrustedEntitiesListType trustedEntitiesListType = new TrustedEntitiesListType();
        lote.setTrustedEntitiesList(trustedEntitiesListType);

        TEType teType = new TEType();
        trustedEntitiesListType.getTrustedEntity().add(teType);

        TrustedEntityInformationType trustedEntityInformation = new TrustedEntityInformationType();
        trustedEntityInformation.setTEName(getNamesType(getLangString("en", "Agence Nationale des Titres Sécurisés")));
        trustedEntityInformation.setTETradeName(getNamesType(getLangString("en", "VATZZ-12345")));
        trustedEntityInformation.setTEAddress(getAddressType(
                Collections.singleton(getPostalAddress("en", "test", "test", "test", "3465", "ZZ")),
                getElectronicAddress(getLangURI("en", "mailto:test@test.fr"), getLangURI("en", "tel:+337848346754"))
        ));
        trustedEntityInformation.setTEInformationURI(getLangUriList(
                getLangURI("en", "http://test.fr"),
                getLangURI("en", "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/ZZ")
        ));
        teType.setTrustedEntityInformation(trustedEntityInformation);

        TrustedEntityServicesListType trustedEntityServicesListType = new TrustedEntityServicesListType();
        teType.setTrustedEntityServices(trustedEntityServicesListType);

        CertificateSource trustedCertificateSource = getTrustedCertificateSourceByPKIName(PKI_NAME);
        for (CertificateToken sdiCertificate : trustedCertificateSource.getCertificates()) {
            TrustedEntityServiceType trustedEntityService = new TrustedEntityServiceType();

            TEServiceInformationType serviceInformation = new TEServiceInformationType();
            trustedEntityService.setServiceInformation(serviceInformation);

            serviceInformation.setServiceName(getNamesType(getLangString("en", DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.O, sdiCertificate.getSubject()))));

            DigitalIdentityListType digitalIdentities = new DigitalIdentityListType();
            DigitalIdentityType digitalIdentityType = new DigitalIdentityType();
            digitalIdentityType.setX509Certificate(sdiCertificate.getEncoded());
            digitalIdentities.getDigitalId().add(digitalIdentityType);
            serviceInformation.setServiceDigitalIdentity(digitalIdentities);

            serviceInformation.setServiceTypeIdentifier(PUB_EAA_SERVICE_TYPE_IDENTIFIER);
            serviceInformation.setServiceStatus(PUB_EAA_SERVICE_CURRENT_STATUS);
            serviceInformation.setStatusStartingTime(toXMLGregorianCalendar(sdiCertificate.getNotBefore()));

            trustedEntityServicesListType.getTrustedEntityService().add(trustedEntityService);
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            LOTEFacade.newFacade().marshall(lote, baos);

            DSSDocument loteToSign = new InMemoryDocument(baos.toByteArray(), "LoTE.xml");

            XAdESService service = new XAdESService(getOfflineCertificateVerifier());
            XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
            signatureParameters.setSigningCertificate(getSigningCert());
            signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

            DSSReference dssReference = new DSSReference();
            dssReference.setId("ref-id");
            dssReference.setUri("");
            dssReference.setContents(loteToSign);
            dssReference.setDigestMethodAlgorithm(signatureParameters.getDigestAlgorithm());

            final List<DSSTransform> transforms = new ArrayList<>();

            EnvelopedSignatureTransform signatureTransform = new EnvelopedSignatureTransform();
            transforms.add(signatureTransform);

            CanonicalizationTransform dssTransform = new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE);
            transforms.add(dssTransform);

            dssReference.setTransforms(transforms);
            signatureParameters.setReferences(Collections.singletonList(dssReference));

            ToBeSigned dataToSign = service.getDataToSign(loteToSign, signatureParameters);
            SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
            DSSDocument signedLoTE = service.signDocument(loteToSign, signatureParameters, signatureValue);
            return signedLoTE;

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

    @Override
    protected String getSigningAlias() {
        return signer;
    }

}
