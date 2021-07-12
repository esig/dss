package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSPDocSpecification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlUserNotice;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBWithSPQualifiersTest extends AbstractXAdESTestSignature {

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
    private static final String SIGNATURE_POLICY_DOCUMENTATION = "http://nowina.lu/signature-policy.pdf";
    private static final String SIGNATURE_POLICY_ORGANIZATION = "Nowina Solutions";
    private static final int[] SIGNATURE_POLICY_NOTICE_NUMBERS = new int[] {1, 2, 3, 4};
    private static final String SIGNATURE_POLICY_EXPLICIT_TEXT = "This is the internal signature policy";

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        Policy signaturePolicy = new Policy();
        signaturePolicy.setId(SIGNATURE_POLICY_ID);
        signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA1);
        signaturePolicy.setDigestValue(new byte[] { 'd', 'i', 'g', 'e', 's', 't', 'v', 'a', 'l', 'u', 'e' });
        signaturePolicy.setSpuri(HTTP_SPURI_TEST);

        UserNotice userNotice = new UserNotice();
        userNotice.setOrganization(SIGNATURE_POLICY_ORGANIZATION);
        userNotice.setNoticeNumbers(SIGNATURE_POLICY_NOTICE_NUMBERS);
        userNotice.setExplicitText(SIGNATURE_POLICY_EXPLICIT_TEXT);
        signaturePolicy.setUserNotice(userNotice);

        SpDocSpecification spDocSpecification = new SpDocSpecification();
        spDocSpecification.setId(SIGNATURE_POLICY_ID);
        spDocSpecification.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        spDocSpecification.setDocumentationReferences(SIGNATURE_POLICY_DOCUMENTATION, Utils.EMPTY_STRING);
        signaturePolicy.setSpDocSpecification(spDocSpecification);

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected SignaturePolicyProvider getSignaturePolicyProvider() {
        return new SignaturePolicyProvider();
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);
        String xmlContent = new String(byteArray);
        assertTrue(xmlContent.contains("description"));
        assertTrue(xmlContent.contains(":DocumentationReferences>"));
        assertTrue(xmlContent.contains(":DocumentationReference>"));
        assertTrue(xmlContent.contains(":SigPolicyQualifiers>"));
        assertTrue(xmlContent.contains(":SigPolicyQualifier>"));
        assertTrue(xmlContent.contains(":SPURI>"));
        assertTrue(xmlContent.contains(":SPUserNotice>"));
        assertTrue(xmlContent.contains(":NoticeRef>"));
        assertTrue(xmlContent.contains(":ExplicitText>"));
        assertTrue(xmlContent.contains(":Organization>"));
        assertTrue(xmlContent.contains(":NoticeNumbers>"));
        assertTrue(xmlContent.contains(":int>"));
        assertTrue(xmlContent.contains(":SPDocSpecification>"));
        assertTrue(xmlContent.contains(HTTP_SPURI_TEST));
    }

    @Override
    protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
        super.verifyDiagnosticData(diagnosticData);
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());

        XmlUserNotice userNotice = signature.getPolicyUserNotice();
        assertNotNull(userNotice);
        assertEquals(SIGNATURE_POLICY_ORGANIZATION, userNotice.getOrganization());
        assertEquals(DSSUtils.toBigIntegerList(SIGNATURE_POLICY_NOTICE_NUMBERS), userNotice.getNoticeNumbers());
        assertEquals(SIGNATURE_POLICY_EXPLICIT_TEXT, userNotice.getExplicitText());

        XmlSPDocSpecification spDocSpecification = signature.getPolicyDocSpecification();
        assertNotNull(spDocSpecification);
        assertEquals(SIGNATURE_POLICY_ID, spDocSpecification.getId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, spDocSpecification.getDescription());
        assertEquals(SIGNATURE_POLICY_DOCUMENTATION, spDocSpecification.getDocumentationReferences().get(0));
        assertEquals(Utils.EMPTY_STRING, spDocSpecification.getDocumentationReferences().get(1));
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
