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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.identifier.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("slow")
class XAdESLevelLTCounterSignatureLevelLTExtensionTest extends AbstractXAdESCounterSignatureTest {

    private XAdESService service;
    private DSSDocument signedDocument;

    private Date signingDate;

    private String signingAlias;

    private XAdESSignatureParameters signatureParameters;
    private XAdESCounterSignatureParameters counterSignatureParameters;
    private XAdESSignatureParameters extensionParameters;

    private ValidationDataEncapsulationStrategy vdStrategy;

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < ValidationDataEncapsulationStrategy.values().length; i++) {
            args.add(Arguments.of(ValidationDataEncapsulationStrategy.values()[i]));
        }
        return args.stream();
    }

    @BeforeEach
    void init() throws Exception {
        signingAlias = RSASSA_PSS_GOOD_USER;

        signedDocument = new FileDocument(new File("src/test/resources/sample.xml"));
        signingDate = new Date();

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        signingAlias = RSA_SHA3_USER;

        counterSignatureParameters = new XAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(signingDate);
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        counterSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
        counterSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        extensionParameters = new XAdESSignatureParameters();
        extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        // init certVerifier and revocation sources after PKI creation
        service = new XAdESService(getCompleteCertificateVerifier());

        // ensure revocation data is after best-signature-time
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, -1);
        service.setTspSource(getGoodTsaByTime(calendar.getTime()));
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
        return counterSignatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        signingAlias = RSASSA_PSS_GOOD_USER;
        return super.sign();
    }

    @Override
    protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, -1);

        signingAlias = RSA_SHA3_USER;
        service.setTspSource(getKeyStoreTSPSourceByNameAndTime(GOOD_TSA_CROSS_CERTIF, calendar.getTime()));
        DSSDocument counterSigned = super.counterSign(signatureDocument, signatureId);

        awaitOneSecond();

        service.setTspSource(getGoodTsa());
        DSSDocument extendedDocument = service.extendDocument(counterSigned, extensionParameters);

        signingAlias = RSASSA_PSS_GOOD_USER;
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        return extendedDocument;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        return certificateVerifier;
    }

    @Override
    public void signAndVerify() {
        // skip
    }

    @ParameterizedTest(name = "XAdES Level LT with Counter Signature Extension {index} : {0}")
    @MethodSource("data")
    void test(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        vdStrategy = validationDataEncapsulationStrategy;
        signatureParameters.setValidationDataEncapsulationStrategy(vdStrategy);
        counterSignatureParameters.setValidationDataEncapsulationStrategy(vdStrategy);
        extensionParameters.setValidationDataEncapsulationStrategy(vdStrategy);
        super.signAndVerify();
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        assertEquals(1, signatures.size());

        AdvancedSignature signature = signatures.iterator().next();
        assertEquals(1, signature.getCounterSignatures().size());
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // do nothing
    }

    @Override
    protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
        // Test that no data is duplicated from counter-signature
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        switch (vdStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                assertEquals(5, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
                assertEquals(3, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(2, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                assertEquals(3, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(2, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
                assertEquals(3, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(2, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            case ANY_VALIDATION_DATA_ONLY:
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
                assertEquals(0, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(5, signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
                break;
            default:
                fail(String.format("The strategy '%s' is not supported!", vdStrategy));
        }
    }

    @Override
    protected void checkRevocationDataEncapsulation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        switch (vdStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                assertEquals(3, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
                assertEquals(1, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(2, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                assertEquals(1, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(1, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(1, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size()); // CRL for counter-sig updated
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
                assertEquals(1, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(2, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            case ANY_VALIDATION_DATA_ONLY:
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
                assertEquals(0, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA).size());
                assertEquals(3, signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA).size());
                break;
            default:
                fail(String.format("The strategy '%s' is not supported!", vdStrategy));
        }
    }

    @Override
    protected TokenIdentifierProvider getTokenIdentifierProvider() {
        return new UserFriendlyIdentifierProvider();
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // do nothing
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // do nothing
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip (different signers)
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return signedDocument;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<XAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
