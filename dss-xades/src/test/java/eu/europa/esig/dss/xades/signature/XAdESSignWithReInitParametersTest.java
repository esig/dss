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
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class XAdESSignWithReInitParametersTest extends AbstractXAdESTestSignature {

    private static XAdESSignatureParameters signatureParameters;
    private static XAdESService service;
    private static CertificateVerifier certificateVerifier;

    private String signingAlias;
    private DSSDocument documentToSign;

    @BeforeAll
    static void initAll() {
        certificateVerifier = new CommonCertificateVerifier();
        service = new XAdESService(certificateVerifier);

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
    }

    private static Stream<Arguments> data() {
        SignatureLevel[] levels = { SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T, SignatureLevel.XAdES_BASELINE_LT,
                SignatureLevel.XAdES_BASELINE_LTA, SignatureLevel.XAdES_C, SignatureLevel.XAdES_X, SignatureLevel.XAdES_XL,
                SignatureLevel.XAdES_A };
        SignaturePackaging[] packagings = { SignaturePackaging.ENVELOPING, SignaturePackaging.ENVELOPED,
                SignaturePackaging.DETACHED, SignaturePackaging.INTERNALLY_DETACHED };
        String[] signers = { GOOD_USER, RSA_SHA3_USER };
        DSSDocument[] documents = { new FileDocument("src/test/resources/sample-with-id.xml"),
                new FileDocument("src/test/resources/sample-with-different-id.xml") };
        return random(levels, packagings, signers, documents);
    }

    static Stream<Arguments> random(SignatureLevel[] levels, SignaturePackaging[] packagings, String[] signers, DSSDocument[] documents) {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < levels.length; i++) {
            for (int j = 0; j < packagings.length; j++) {
                for (int m = 0; m < signers.length; m++) {
                    for (int n = 0; n < documents.length; n++) {
                        args.add(Arguments.of(levels[i], packagings[j], signers[m], documents[n]));
                    }
                }
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Sign XAdES {index} : {0} - {1} - {2} - {3}")
    @MethodSource("data")
    void init(SignatureLevel level, SignaturePackaging packaging, String signer, DSSDocument document) {
        documentToSign = document;
        signingAlias = signer;

        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(level);
        signatureParameters.setSignaturePackaging(packaging);

        CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAIASource(completeCertificateVerifier.getAIASource());
        certificateVerifier.setCrlSource(completeCertificateVerifier.getCrlSource());
        certificateVerifier.setOcspSource(completeCertificateVerifier.getOcspSource());
        certificateVerifier.setTrustedCertSources(completeCertificateVerifier.getTrustedCertSources());

        service.setTspSource(getGoodTsa());

        super.signAndVerify();
    }

    @Override
    protected DSSDocument sign() {
        XAdESService service = getService();

        DSSDocument toBeSigned = getDocumentToSign();
        XAdESSignatureParameters params = getSignatureParameters();

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        params.reinit();

        return service.signDocument(toBeSigned, params, signatureValue);
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        if (SignaturePackaging.DETACHED.equals(signatureParameters.getSignaturePackaging())) {
            return Arrays.asList(getDocumentToSign());
        }
        return Collections.emptyList();
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        if (!SignatureLevel.XAdES_C.equals(signatureParameters.getSignatureLevel()) &&
                !SignatureLevel.XAdES_X.equals(signatureParameters.getSignatureLevel())) {
            super.checkOrphanTokens(diagnosticData);
        }
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected XAdESService getService() {
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
        return signingAlias;
    }

}
