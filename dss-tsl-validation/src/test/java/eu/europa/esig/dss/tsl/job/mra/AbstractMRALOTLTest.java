package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigNamespace;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.tsl.dto.condition.QCStatementCondition;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.trustedlist.enums.Assert;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractMRALOTLTest extends PKIFactoryAccess {

    protected static final String LOTL_LOCATION = "https://esignature.ec.europa.eu/efda/intl-pilot/api/v1/intl-pilot/mra_lotl.xml";
    protected static final String ZZ_TL_LOCATION = "https://esignature.ec.europa.eu/efda/intl-pilot/api/v1/intl-pilot/tl/mra_tl_zz.xml";

    protected static final String SIGNER_LOTL_NAME = "ZZ-LOTL-signer";
    protected static final String SIGNER_ZZ_TL_NAME = "ZZ-TL-signer";
    private static final String TRUSTED_ROOT_CA_NAME = "Test-QTSP-1-RootCA-from-ZZ";

    private static final DSSDocument ORIGINAL_LOTL = new FileDocument("src/test/resources/mra-lotl.xml");
    private static final DSSDocument ORIGINAL_TL = new FileDocument("src/test/resources/mra-zz-tl.xml");

    private static final DSSNamespace TL_NAMESPACE = new DSSNamespace("http://uri.etsi.org/02231/v2#", "tl");
    private static final DSSNamespace MRA_NAMESPACE = new DSSNamespace("http://ec.europa.eu/tools/lotl/mra/schema/v2#", "mra");
    private static final DSSNamespace CONDITION_NAMESPACE = new DSSNamespace("http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#", "ns5");

    private static final DSSDocument DOC_TO_SIGN = new InMemoryDocument("Hello World".getBytes());

    private static String signer;

    @BeforeAll
    public static void init() {
        DomUtils.registerNamespace(XMLDSigNamespace.NS);
        DomUtils.registerNamespace(XAdESNamespaces.XADES_132);
        DomUtils.registerNamespace(TL_NAMESPACE);
        DomUtils.registerNamespace(MRA_NAMESPACE);
        DomUtils.registerNamespace(CONDITION_NAMESPACE);
    }

    @Override
    protected DataLoader getFileCacheDataLoader() {
        FileCacheDataLoader fileCacheDataLoader = (FileCacheDataLoader) super.getFileCacheDataLoader();
        fileCacheDataLoader.setCacheExpirationTime(0);
        return fileCacheDataLoader;
    }

    protected DSSDocument createZZTL() {
        Document tlDocument = DomUtils.buildDOM(ORIGINAL_TL);
        Element lotlCertElement = DomUtils.getElement(tlDocument.getDocumentElement(),
                "./tl:SchemeInformation/tl:PointersToOtherTSL/tl:OtherTSLPointer/tl:ServiceDigitalIdentities/tl:ServiceDigitalIdentity/tl:DigitalId/tl:X509Certificate");
        Text firstChild = (Text) lotlCertElement.getFirstChild();
        firstChild.setNodeValue(Utils.toBase64(getCertificate(SIGNER_LOTL_NAME).getEncoded()));

        Element tspServiceSI = DomUtils.getElement(tlDocument.getDocumentElement(),
                "./tl:TrustServiceProviderList/tl:TrustServiceProvider/tl:TSPServices/tl:TSPService/tl:ServiceInformation");
        Element originalTspServiceSDI = DomUtils.getElement(tspServiceSI,"./tl:ServiceDigitalIdentity");

        Element newTspServiceSDI = tlDocument.createElementNS(tspServiceSI.getNamespaceURI(), "ServiceDigitalIdentity");
        tspServiceSI.replaceChild(newTspServiceSDI, originalTspServiceSDI);


        CertificateToken rootCA = getCertificate(TRUSTED_ROOT_CA_NAME);

        Element digitalId = tlDocument.createElementNS(tspServiceSI.getNamespaceURI(), "DigitalId");
        newTspServiceSDI.appendChild(digitalId);

        Element x509Certificate = tlDocument.createElementNS(tspServiceSI.getNamespaceURI(), "X509Certificate");
        digitalId.appendChild(x509Certificate);

        Text valueNode = tlDocument.createTextNode(Utils.toBase64(rootCA.getEncoded()));
        x509Certificate.appendChild(valueNode);

        digitalId = tlDocument.createElementNS(tspServiceSI.getNamespaceURI(), "DigitalId");
        newTspServiceSDI.appendChild(digitalId);

        Element x509SubjectName = tlDocument.createElementNS(tspServiceSI.getNamespaceURI(), "X509SubjectName");
        digitalId.appendChild(x509SubjectName);

        valueNode = tlDocument.createTextNode(DSSASN1Utils.getSubjectCommonName(rootCA));
        x509SubjectName.appendChild(valueNode);

        digitalId = tlDocument.createElementNS(tspServiceSI.getNamespaceURI(), "DigitalId");
        newTspServiceSDI.appendChild(digitalId);

        Element x509SKI = tlDocument.createElementNS(tspServiceSI.getNamespaceURI(), "X509SKI");
        digitalId.appendChild(x509SKI);

        valueNode = tlDocument.createTextNode(Utils.toBase64(DSSASN1Utils.getSki(rootCA)));
        x509SKI.appendChild(valueNode);


        Element signature = DomUtils.getElement(tlDocument.getDocumentElement(),
                "//ds:Signature");
        tlDocument.getDocumentElement().removeChild(signature);


        signer = SIGNER_ZZ_TL_NAME;
        DSSDocument tlToSign = new InMemoryDocument(DSSXMLUtils.serializeNode(tlDocument));

        XAdESService service = new XAdESService(getOfflineCertificateVerifier());
        XAdESSignatureParameters signatureParameters = new TrustedListSignatureParametersBuilder(getSigningCert(), tlToSign).build();
        ToBeSigned dataToSign = service.getDataToSign(tlToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedTL = service.signDocument(tlToSign, signatureParameters, signatureValue);
        return signedTL;
    }

    protected DSSDocument createZZLOTL() {
        Document lotlDocument = DomUtils.buildDOM(ORIGINAL_LOTL);

        NodeList tslPointers = DomUtils.getNodeList(lotlDocument.getDocumentElement(), "./tl:SchemeInformation/tl:PointersToOtherTSL/tl:OtherTSLPointer");
        assertEquals(44, tslPointers.getLength());

        Element zzTslPointer = (Element) tslPointers.item(43);

        Element tlCertElement = DomUtils.getElement(zzTslPointer,
                "./tl:ServiceDigitalIdentities/tl:ServiceDigitalIdentity/tl:DigitalId/tl:X509Certificate");
        Text firstChild = (Text) tlCertElement.getFirstChild();
        firstChild.setNodeValue(Utils.toBase64(getCertificate(SIGNER_ZZ_TL_NAME).getEncoded()));


        Element mraInformation = DomUtils.getElement(zzTslPointer,
                "//mra:MutualRecognitionAgreementInformation");
        configureMRAInformationElement(lotlDocument, mraInformation);


        Element signature = DomUtils.getElement(lotlDocument.getDocumentElement(),
                "//ds:Signature");
        lotlDocument.getDocumentElement().removeChild(signature);


        signer = SIGNER_LOTL_NAME;
        DSSDocument lotlToSign = new InMemoryDocument(DSSXMLUtils.serializeNode(lotlDocument));

        XAdESService service = new XAdESService(getOfflineCertificateVerifier());
        XAdESSignatureParameters signatureParameters = new TrustedListSignatureParametersBuilder(getSigningCert(), lotlToSign).build();
        ToBeSigned dataToSign = service.getDataToSign(lotlToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedLOTL = service.signDocument(lotlToSign, signatureParameters, signatureValue);
        return signedLOTL;
    }

    protected void configureMRAInformationElement(Document document, Element mraInformation) {
        String trustServiceLegalIdentifier = getTrustServiceLegalIdentifier();
        if (Utils.isStringNotEmpty(trustServiceLegalIdentifier)) {
            Element trustServiceLegalIdentifierElement = DomUtils.getElement(mraInformation,
                    "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceLegalIdentifier");
            setText(trustServiceLegalIdentifierElement, trustServiceLegalIdentifier);
        }

        Element trustServiceTSLTypeListPointedParty = DomUtils.getElement(mraInformation,
                "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceTSLTypeEquivalenceList/mra:TrustServiceTSLTypeListPointedParty");

        String serviceTypeIdentifierPointedParty = getTrustServiceTSLTypeListPointedPartyServiceTypeIdentifier();
        if (Utils.isStringNotEmpty(serviceTypeIdentifierPointedParty)) {
            Element serviceTypeIdentifierElement = DomUtils.getElement(trustServiceTSLTypeListPointedParty,
                    "./mra:TrustServiceTSLType/tl:ServiceTypeIdentifier");
            setText(serviceTypeIdentifierElement, serviceTypeIdentifierPointedParty);
        }

        String asiPointedParty = getTrustServiceTSLTypeListPointedPartyAdditionalServiceInformation();
        if (Utils.isStringNotEmpty(asiPointedParty)) {
            Element trustServiceTSLType = DomUtils.getElement(trustServiceTSLTypeListPointedParty,
                    "./mra:TrustServiceTSLType");
            NodeList asiList = DomUtils.getNodeList(trustServiceTSLType, "./tl:AdditionalServiceInformation");
            if (asiList != null && asiList.getLength() > 0) {
                for (int i = 0; i < asiList.getLength(); i++) {
                    trustServiceTSLType.removeChild(asiList.item(i));
                }
            }
            Element newAsiElement = document.createElementNS(TL_NAMESPACE.getUri(), "AdditionalServiceInformation");
            trustServiceTSLType.appendChild(newAsiElement);

            Element uriElement = document.createElementNS(TL_NAMESPACE.getUri(), "URI");
            newAsiElement.appendChild(uriElement);

            uriElement.setAttribute("xml:lang", "en");
            setText(uriElement, asiPointedParty);
        }

        Element trustServiceTSLTypeListPointingParty = DomUtils.getElement(mraInformation,
                "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceTSLTypeEquivalenceList/mra:TrustServiceTSLTypeListPointingParty");

        String serviceTypeIdentifierPointingParty = getTrustServiceTSLTypeListPointingPartyServiceTypeIdentifier();
        if (Utils.isStringNotEmpty(serviceTypeIdentifierPointingParty)) {
            Element serviceTypeIdentifierElement = DomUtils.getElement(trustServiceTSLTypeListPointingParty,
                    "./mra:TrustServiceTSLType/tl:ServiceTypeIdentifier");
            setText(serviceTypeIdentifierElement, serviceTypeIdentifierPointingParty);
        }

        String asiPointingParty = getTrustServiceTSLTypeListPointingPartyAdditionalServiceInformation();
        if (Utils.isStringNotEmpty(asiPointingParty)) {
            Element trustServiceTSLType = DomUtils.getElement(trustServiceTSLTypeListPointingParty,
                    "./mra:TrustServiceTSLType");
            NodeList asiList = DomUtils.getNodeList(trustServiceTSLType, "./tl:AdditionalServiceInformation");
            if (asiList != null && asiList.getLength() > 0) {
                for (int i = 0; i < asiList.getLength(); i++) {
                    trustServiceTSLType.removeChild(asiList.item(i));
                }
            }
            Element newAsiElement = document.createElementNS(TL_NAMESPACE.getUri(), "AdditionalServiceInformation");
            trustServiceTSLType.appendChild(newAsiElement);

            Element uriElement = document.createElementNS(TL_NAMESPACE.getUri(), "URI");
            newAsiElement.appendChild(uriElement);

            uriElement.setAttribute("xml:lang", "en");
            setText(uriElement, asiPointingParty);
        }

        String trustServiceEquivalenceStatus = getTrustServiceEquivalenceStatus();
        if (Utils.isStringNotEmpty(trustServiceEquivalenceStatus)) {
            Element trustServiceEquivalenceStatusElement = DomUtils.getElement(mraInformation,
                    "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceEquivalenceStatus");
            setText(trustServiceEquivalenceStatusElement, trustServiceEquivalenceStatus);
        }

        Date trustServiceEquivalenceStatusStartingTime = getTrustServiceEquivalenceStatusStartingTime();
        if (trustServiceEquivalenceStatusStartingTime != null) {
            String timeString = DSSUtils.formatDateToRFC(trustServiceEquivalenceStatusStartingTime);
            Element trustServiceEquivalenceStatusStartingTimeElement = DomUtils.getElement(mraInformation,
                    "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceEquivalenceStatusStartingTime");
            setText(trustServiceEquivalenceStatusStartingTimeElement, timeString);
        }

        String validEquivalencePointedParty = getTrustServiceTSLTypeListPointedPartyTrustServiceTSLStatusValidEquivalence();
        if (Utils.isStringNotEmpty(validEquivalencePointedParty)) {
            Element trustServiceTSLStatusListPointedParty = DomUtils.getElement(mraInformation,
                    "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceTSLStatusEquivalenceList/mra:TrustServiceTSLStatusValidEquivalence/mra:TrustServiceTSLStatusListPointedParty/tl:ServiceStatus");
            setText(trustServiceTSLStatusListPointedParty, validEquivalencePointedParty);
        }

        String validEquivalencePointingParty = getTrustServiceTSLTypeListPointingPartyTrustServiceTSLStatusValidEquivalence();
        if (Utils.isStringNotEmpty(validEquivalencePointingParty)) {
            Element trustServiceTSLStatusListPointingParty = DomUtils.getElement(mraInformation,
                    "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceTSLStatusEquivalenceList/mra:TrustServiceTSLStatusValidEquivalence/mra:TrustServiceTSLStatusListPointingParty/tl:ServiceStatus");
            setText(trustServiceTSLStatusListPointingParty, validEquivalencePointingParty);
        }

        String invalidEquivalencePointedParty = getTrustServiceTSLTypeListPointedPartyTrustServiceTSLStatusInvalidEquivalence();
        if (Utils.isStringNotEmpty(invalidEquivalencePointedParty)) {
            Element trustServiceTSLStatusListPointedParty = DomUtils.getElement(mraInformation,
                    "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceTSLStatusEquivalenceList/mra:TrustServiceTSLStatusInvalidEquivalence/mra:TrustServiceTSLStatusListPointedParty/tl:ServiceStatus");
            setText(trustServiceTSLStatusListPointedParty, invalidEquivalencePointedParty);
        }

        String invalidEquivalencePointingParty = getTrustServiceTSLTypeListPointingPartyTrustServiceTSLStatusInvalidEquivalence();
        if (Utils.isStringNotEmpty(invalidEquivalencePointingParty)) {
            Element trustServiceTSLStatusListPointingParty = DomUtils.getElement(mraInformation,
                    "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceTSLStatusEquivalenceList/mra:TrustServiceTSLStatusInvalidEquivalence/mra:TrustServiceTSLStatusListPointingParty/tl:ServiceStatus");
            setText(trustServiceTSLStatusListPointingParty, invalidEquivalencePointingParty);
        }

        Element qcComplianceCertificateContentReferenceEquivalence = null;
        Element qcTypeCertificateContentReferenceEquivalence = null;
        Element qcQSCDCertificateContentReferenceEquivalence = null;

        NodeList certificateContentReferencesEquivalenceList = DomUtils.getNodeList(mraInformation,
                "./mra:TrustServiceEquivalenceInformation/mra:CertificateContentReferencesEquivalenceList/mra:CertificateContentReferenceEquivalence");
        for (int i = 0; i < certificateContentReferencesEquivalenceList.getLength(); i++) {
            Element certificateContentReferencesEquivalence = (Element) certificateContentReferencesEquivalenceList.item(i);
            Element certificateContentReferenceEquivalenceContext = DomUtils.getElement(certificateContentReferencesEquivalence,
                    "./mra:CertificateContentReferenceEquivalenceContext");
            if (certificateContentReferenceEquivalenceContext != null) {
                Text textValue = (Text) certificateContentReferenceEquivalenceContext.getFirstChild();
                if (MRAEquivalenceContext.QC_COMPLIANCE.getUri().equals(textValue.getWholeText())) {
                    qcComplianceCertificateContentReferenceEquivalence = certificateContentReferencesEquivalence;
                } else if (MRAEquivalenceContext.QC_TYPE.getUri().equals(textValue.getWholeText())) {
                    qcTypeCertificateContentReferenceEquivalence = certificateContentReferencesEquivalence;
                } else if (MRAEquivalenceContext.QC_QSCD.getUri().equals(textValue.getWholeText())) {
                    qcQSCDCertificateContentReferenceEquivalence = certificateContentReferencesEquivalence;
                }
            }
        }

        assertNotNull(qcComplianceCertificateContentReferenceEquivalence);
        assertNotNull(qcTypeCertificateContentReferenceEquivalence);
        assertNotNull(qcQSCDCertificateContentReferenceEquivalence);

        Element qcComplianceCertificateContentDeclarationPointedPartyElement = DomUtils.getElement(qcComplianceCertificateContentReferenceEquivalence,
                "./mra:CertificateContentDeclarationPointedParty");

        Assert qcCompliancePointedPartyAssertStatus = getCertificateContentDeclarationPointedPartyQcComplianceAssertStatus();
        if (qcCompliancePointedPartyAssertStatus != null) {
            qcComplianceCertificateContentDeclarationPointedPartyElement.setAttribute("assert", qcCompliancePointedPartyAssertStatus.getValue());
        }

        Condition qcCompliancePointedParty = getCertificateContentDeclarationPointedPartyQcCompliance();
        if (qcCompliancePointedParty != null) {
            removeAllChildren(qcComplianceCertificateContentDeclarationPointedPartyElement);
            setCondition(document, qcComplianceCertificateContentDeclarationPointedPartyElement, qcCompliancePointedParty);
        }

        Element qcComplianceCertificateContentDeclarationPointingPartyElement = DomUtils.getElement(qcComplianceCertificateContentReferenceEquivalence,
                "./mra:CertificateContentDeclarationPointingParty");

        Assert qcCompliancePointingPartyAssertStatus = getCertificateContentDeclarationPointingPartyQcComplianceAssertStatus();
        if (qcCompliancePointingPartyAssertStatus != null) {
            qcComplianceCertificateContentDeclarationPointingPartyElement.setAttribute("assert", qcCompliancePointingPartyAssertStatus.getValue());
        }

        Condition qcCompliancePointingParty = getCertificateContentDeclarationPointingPartyQcCompliance();
        if (qcCompliancePointingParty != null) {
            removeAllChildren(qcComplianceCertificateContentDeclarationPointingPartyElement);
            setCondition(document, qcComplianceCertificateContentDeclarationPointingPartyElement, qcCompliancePointingParty);
        }

        Element qcTypeCertificateContentDeclarationPointedPartyElement = DomUtils.getElement(qcTypeCertificateContentReferenceEquivalence,
                "./mra:CertificateContentDeclarationPointedParty");

        Assert qcTypePointedPartyAssertStatus = getCertificateContentDeclarationPointedPartyQcTypeAssertStatus();
        if (qcTypePointedPartyAssertStatus != null) {
            qcTypeCertificateContentDeclarationPointedPartyElement.setAttribute("assert", qcTypePointedPartyAssertStatus.getValue());
        }

        Condition qcTypePointedParty = getCertificateContentDeclarationPointedPartyQcType();
        if (qcTypePointedParty != null) {
            removeAllChildren(qcTypeCertificateContentDeclarationPointedPartyElement);
            setCondition(document, qcTypeCertificateContentDeclarationPointedPartyElement, qcTypePointedParty);
        }

        Element qcTypeCertificateContentDeclarationPointingPartyElement = DomUtils.getElement(qcTypeCertificateContentReferenceEquivalence,
                "./mra:CertificateContentDeclarationPointingParty");

        Assert qcTypePointingPartyAssertStatus = getCertificateContentDeclarationPointingPartyQcTypeAssertStatus();
        if (qcTypePointingPartyAssertStatus != null) {
            qcTypeCertificateContentDeclarationPointingPartyElement.setAttribute("assert", qcTypePointingPartyAssertStatus.getValue());
        }

        Condition qcTypePointingParty = getCertificateContentDeclarationPointingPartyQcType();
        if (qcTypePointingParty != null) {
            removeAllChildren(qcTypeCertificateContentDeclarationPointingPartyElement);
            setCondition(document, qcTypeCertificateContentDeclarationPointingPartyElement, qcTypePointingParty);
        }

        Element qcQSCDCertificateContentDeclarationPointedPartyElement = DomUtils.getElement(qcQSCDCertificateContentReferenceEquivalence,
                "./mra:CertificateContentDeclarationPointedParty");

        Assert qcQSCDPointedPartyAssertStatus = getCertificateContentDeclarationPointedPartyQcQSCDAssertStatus();
        if (qcQSCDPointedPartyAssertStatus != null) {
            qcQSCDCertificateContentDeclarationPointedPartyElement.setAttribute("assert", qcQSCDPointedPartyAssertStatus.getValue());
        }

        Condition qcQSCDPointedParty = getCertificateContentDeclarationPointedPartyQcQSCD();
        if (qcQSCDPointedParty != null) {
            removeAllChildren(qcQSCDCertificateContentDeclarationPointedPartyElement);
            setCondition(document, qcQSCDCertificateContentDeclarationPointedPartyElement, qcQSCDPointedParty);
        }

        Element qcQSCDCertificateContentDeclarationPointingPartyElement = DomUtils.getElement(qcQSCDCertificateContentReferenceEquivalence,
                "./mra:CertificateContentDeclarationPointingParty");

        Assert qcQSCDPointingPartyAssertStatus = getCertificateContentDeclarationPointingPartyQcQSCDAssertStatus();
        if (qcQSCDPointingPartyAssertStatus != null) {
            qcQSCDCertificateContentDeclarationPointingPartyElement.setAttribute("assert", qcQSCDPointingPartyAssertStatus.getValue());
        }

        Condition qcQSCDcQSCDPointingParty = getCertificateContentDeclarationPointingPartyQcQSCD();
        if (qcQSCDcQSCDPointingParty != null) {
            removeAllChildren(qcQSCDCertificateContentDeclarationPointingPartyElement);
            setCondition(document, qcTypeCertificateContentDeclarationPointingPartyElement, qcQSCDcQSCDPointingParty);
        }

        Map<String, String> qualifierEquivalenceMap = getQualifierEquivalenceMap();
        if (Utils.isMapNotEmpty(qualifierEquivalenceMap)) {
            Element qualifierEquivalenceListElement = DomUtils.getElement(mraInformation,
                    "./mra:TrustServiceEquivalenceInformation/mra:TrustServiceTSLQualificationExtensionEquivalenceList/mra:QualifierEquivalenceList");
            removeAllChildren(qualifierEquivalenceListElement);
            for (Map.Entry<String, String> entry : qualifierEquivalenceMap.entrySet()) {
                Element qualifierEquivalenceElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QualifierEquivalence");
                qualifierEquivalenceListElement.appendChild(qualifierEquivalenceElement);

                Element qualifierPointingPartyElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QualifierPointingParty");
                qualifierEquivalenceElement.appendChild(qualifierPointingPartyElement);
                qualifierPointingPartyElement.setAttribute("uri", entry.getValue());

                Element qualifierPointedPartyElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QualifierPointedParty");
                qualifierEquivalenceElement.appendChild(qualifierPointedPartyElement);
                qualifierPointedPartyElement.setAttribute("uri", entry.getKey());
            }
        }

    }

    protected String getTrustServiceLegalIdentifier() {
        return null;
    }

    protected String getTrustServiceTSLTypeListPointedPartyServiceTypeIdentifier() {
        return null;
    }

    protected String getTrustServiceTSLTypeListPointedPartyAdditionalServiceInformation() {
        return null;
    }

    protected String getTrustServiceTSLTypeListPointingPartyServiceTypeIdentifier() {
        return null;
    }

    protected String getTrustServiceTSLTypeListPointingPartyAdditionalServiceInformation() {
        return null;
    }

    protected String getTrustServiceEquivalenceStatus() {
        return null;
    }

    protected Date getTrustServiceEquivalenceStatusStartingTime() {
        return null;
    }

    protected String getTrustServiceTSLTypeListPointedPartyTrustServiceTSLStatusValidEquivalence() {
        return null;
    }

    protected String getTrustServiceTSLTypeListPointingPartyTrustServiceTSLStatusValidEquivalence() {
        return null;
    }

    protected String getTrustServiceTSLTypeListPointedPartyTrustServiceTSLStatusInvalidEquivalence() {
        return null;
    }

    protected String getTrustServiceTSLTypeListPointingPartyTrustServiceTSLStatusInvalidEquivalence() {
        return null;
    }

    protected Assert getCertificateContentDeclarationPointedPartyQcComplianceAssertStatus() {
        return null;
    }

    protected Condition getCertificateContentDeclarationPointedPartyQcCompliance() {
        return null;
    }

    protected Assert getCertificateContentDeclarationPointingPartyQcComplianceAssertStatus() {
        return null;
    }

    protected Condition getCertificateContentDeclarationPointingPartyQcCompliance() {
        return null;
    }

    protected Assert getCertificateContentDeclarationPointedPartyQcTypeAssertStatus() {
        return null;
    }

    protected Condition getCertificateContentDeclarationPointedPartyQcType() {
        return null;
    }

    protected Assert getCertificateContentDeclarationPointingPartyQcTypeAssertStatus() {
        return null;
    }

    protected Condition getCertificateContentDeclarationPointingPartyQcType() {
        return null;
    }

    protected Assert getCertificateContentDeclarationPointedPartyQcQSCDAssertStatus() {
        return null;
    }

    protected Condition getCertificateContentDeclarationPointedPartyQcQSCD() {
        return null;
    }

    protected Assert getCertificateContentDeclarationPointingPartyQcQSCDAssertStatus() {
        return null;
    }

    protected Condition getCertificateContentDeclarationPointingPartyQcQSCD() {
        return null;
    }

    protected Map<String, String> getQualifierEquivalenceMap() {
        return null;
    }

    private void setText(Element element, String text) {
        Text textValue = (Text) element.getFirstChild();
        if (textValue != null) {
            textValue.setNodeValue(text);
        } else {
            textValue = element.getOwnerDocument().createTextNode(text);
            element.appendChild(textValue);
        }
    }

    public void removeAllChildren(Node node)
    {
        while (node.getFirstChild() != null) {
            node.removeChild(node.getFirstChild());
        }
    }

    private void setCondition(Document document, Element element, Condition condition) {
        if (condition instanceof QCStatementCondition) {
            Element otherCriteriaListElement = document.createElementNS(CONDITION_NAMESPACE.getUri(), "ns5:otherCriteriaList");
            element.appendChild(otherCriteriaListElement);
            element = otherCriteriaListElement;
        }
        setConditionRecursively(document, element, condition);
    }

    private void setConditionRecursively(Document document, Element element, Condition condition) {
        if (condition instanceof CompositeCondition) {
            CompositeCondition compositeCondition = (CompositeCondition) condition;
            Assert matchingCriteriaIndicator = compositeCondition.getMatchingCriteriaIndicator();
            Element criteriaListElement = document.createElementNS(CONDITION_NAMESPACE.getUri(), "ns5:CriteriaList");
            element.appendChild(criteriaListElement);
            criteriaListElement.setAttribute("assert", matchingCriteriaIndicator.getValue());

            List<Condition> children = compositeCondition.getChildren();
            if (Utils.isCollectionNotEmpty(children)) {
                Element otherCriteriaListElement = document.createElementNS(CONDITION_NAMESPACE.getUri(), "ns5:otherCriteriaList");
                criteriaListElement.appendChild(otherCriteriaListElement);
                for (Condition child : children) {
                    setConditionRecursively(document, otherCriteriaListElement, child);
                }
            }

        } else if (condition instanceof QCStatementCondition) {
            QCStatementCondition qcStatementCondition = (QCStatementCondition) condition;
            Element qcStatementSetElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcStatementSet");
            element.appendChild(qcStatementSetElement);

            if (Utils.isStringNotEmpty(qcStatementCondition.getOid())) {
                Element qcStatementElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcStatement");
                qcStatementSetElement.appendChild(qcStatementElement);
                addUrnOid(document, qcStatementElement, qcStatementCondition.getOid());
            }
            
            if (Utils.isStringNotEmpty(qcStatementCondition.getType())) {
                Element qcStatementElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcStatement");
                qcStatementSetElement.appendChild(qcStatementElement);
                addUrnOid(document, qcStatementElement, "urn:oid:0.4.0.1862.1.6");

                Element qcStatementInfoElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcStatementInfo");
                qcStatementElement.appendChild(qcStatementInfoElement);
                Element qcTypeElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcType");
                qcStatementInfoElement.appendChild(qcTypeElement);

                Element identifierElement = document.createElementNS(XAdESNamespaces.XADES_132.getUri(), "ns4:Identifier");
                qcTypeElement.appendChild(identifierElement);
                identifierElement.setAttribute("Qualifier", "OIDAsURN");
                setText(identifierElement, qcStatementCondition.getType());
            }

            if (Utils.isStringNotEmpty(qcStatementCondition.getLegislation())) {
                Element qcStatementElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcStatement");
                qcStatementSetElement.appendChild(qcStatementElement);
                addUrnOid(document, qcStatementElement, "urn:oid:0.4.0.1862.1.7");

                Element qcStatementInfoElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcStatementInfo");
                qcStatementElement.appendChild(qcStatementInfoElement);
                Element qcCClegislationElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcCClegislation");
                qcStatementInfoElement.appendChild(qcCClegislationElement);
                setText(qcCClegislationElement, qcStatementCondition.getLegislation());
            }

        } else {
            fail(String.format("Not supported Condition class : %s", condition.getClass()));
        }
    }

    private void addUrnOid(Document document, Element element, String oid) {
        Element qcStatementIdElement = document.createElementNS(MRA_NAMESPACE.getUri(), "mra:QcStatementId");
        element.appendChild(qcStatementIdElement);

        Element identifierElement = document.createElementNS(XAdESNamespaces.XADES_132.getUri(), "ns4:Identifier");
        qcStatementIdElement.appendChild(identifierElement);
        identifierElement.setAttribute("Qualifier", "OIDAsURN");
        setText(identifierElement,oid);
    }

    @Test
    public void test() throws Exception {
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


        signer = getSignerName();

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        XAdESService service = new XAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(DOC_TO_SIGN, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(DOC_TO_SIGN, signatureParameters, signatureValue);

        DocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

        CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
        completeCertificateVerifier.addTrustedCertSources(trustedCertificateSource);
        documentValidator.setCertificateVerifier(completeCertificateVerifier);

        Reports reports = documentValidator.validateDocument();
        verifyReports(reports);
    }

    protected void verifyReports(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        verifyDiagnosticData(diagnosticData);
        SimpleReport simpleReport = reports.getSimpleReport();
        verifySimpleReport(simpleReport);
    }

    protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
        verifyCertificates(diagnosticData);
        verifySigningCertificate(diagnosticData);
    }

    protected void verifyCertificates(DiagnosticData diagnosticData) {
        List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
        assertTrue(Utils.isCollectionNotEmpty(usedCertificates));
        for (CertificateWrapper certificateWrapper : usedCertificates) {
            List<TrustedServiceWrapper> trustedServices = certificateWrapper.getTrustedServices();
            for (TrustedServiceWrapper trustedServiceWrapper : trustedServices) {
                assertEquals(isEnactedMRA(), trustedServiceWrapper.isEnactedMRA());
                if (isEnactedMRA()) {
                    assertNotNull(trustedServiceWrapper.getOriginalTCType());
                    assertNotNull(trustedServiceWrapper.getOriginalTCStatus());
                }
            }
        }
    }

    protected void verifySigningCertificate(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustedServiceWrapper> trustedServices = signingCertificate.getTrustedServices();
        assertTrue(Utils.isCollectionNotEmpty(trustedServices));

        boolean enactedMRAFound = false;
        for (TrustedServiceWrapper trustedServiceWrapper : trustedServices) {
            if (trustedServiceWrapper.isEnactedMRA()) {
                if (getTrustServiceLegalIdentifier() != null) {
                    assertEquals(getTrustServiceLegalIdentifier(), trustedServiceWrapper.getMraTrustServiceLegalIdentifier());
                }
                if (getTrustServiceTSLTypeListPointingPartyServiceTypeIdentifier() != null) {
                    assertEquals(getTrustServiceTSLTypeListPointingPartyServiceTypeIdentifier(), trustedServiceWrapper.getType());
                }
                if (getTrustServiceTSLTypeListPointingPartyAdditionalServiceInformation() != null) {
                    assertEquals(getTrustServiceTSLTypeListPointingPartyAdditionalServiceInformation(), trustedServiceWrapper.getAdditionalServiceInfos().iterator().next());
                }
                if (getTrustServiceEquivalenceStatusStartingTime() != null) {
                    assertEquals(DSSUtils.formatDateToRFC(getTrustServiceEquivalenceStatusStartingTime()),
                            DSSUtils.formatDateToRFC(trustedServiceWrapper.getMraTrustServiceEquivalenceStatusStartingTime()));
                }
                if (getTrustServiceTSLTypeListPointingPartyTrustServiceTSLStatusValidEquivalence() != null) {
                    assertEquals(getTrustServiceTSLTypeListPointingPartyTrustServiceTSLStatusValidEquivalence(), trustedServiceWrapper.getStatus());
                }
                if (getQualifierEquivalenceMap() != null) {
                    for (Map.Entry<String, String> mapEntry : getQualifierEquivalenceMap().entrySet()) {
                        if (trustedServiceWrapper.getOriginalCapturedQualifiers().contains(mapEntry.getKey())) {
                            assertTrue(trustedServiceWrapper.getCapturedQualifiers().contains(mapEntry.getValue()));
                        }
                    }
                }
                enactedMRAFound = true;
            }
        }
        assertEquals(isEnactedMRA(), enactedMRAFound);
        assertEquals(getMRAEnactedTrustServiceLegalIdentifier(), signingCertificate.getMRAEnactedTrustServiceLegalIdentifier());
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        assertEquals(getFinalIndication(), simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(getFinalSignatureQualification(), simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
    }

    protected abstract Indication getFinalIndication();

    protected abstract SignatureQualification getFinalSignatureQualification();

    protected abstract boolean isEnactedMRA();

    protected abstract String getMRAEnactedTrustServiceLegalIdentifier();

    @Override
    protected String getSigningAlias() {
        return signer;
    }

    protected String getSignerName() {
        return "John Doe";
    }

}
