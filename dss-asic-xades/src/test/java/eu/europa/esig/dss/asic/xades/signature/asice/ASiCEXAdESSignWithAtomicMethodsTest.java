/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class ASiCEXAdESSignWithAtomicMethodsTest extends AbstractASiCEXAdESTestSignature {

    private static ASiCWithXAdESSignatureParameters signatureParameters;
    private static ASiCWithXAdESService service;
    private static CertificateVerifier certificateVerifier;

    private String signingAlias;
    private DSSDocument documentToSign;

    @BeforeAll
    static void initAll() {
        certificateVerifier = new CommonCertificateVerifier();
        service = new ASiCWithXAdESService(certificateVerifier);
    }

    private static Stream<Arguments> data() {
        SignatureLevel[] levels = { SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T,
                SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA };
        String[] signers = { GOOD_USER, RSA_SHA3_USER };
        DSSDocument[] documents = { new FileDocument("src/test/resources/signable/test.txt"),
                new FileDocument("src/test/resources/signable/test.zip") };
        return random(levels, signers, documents);
    }

    static Stream<Arguments> random(SignatureLevel[] levels, String[] signers, DSSDocument[] documents) {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < levels.length; i++) {
            for (int m = 0; m < signers.length; m++) {
                for (int n = 0; n < documents.length; n++) {
                    args.add(Arguments.of(levels[i], signers[m], documents[n]));
                }
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Sign XAdES {index} : {0} - {1} - {2}")
    @MethodSource("data")
    void init(SignatureLevel level, String signer, DSSDocument document) {
        documentToSign = document;
        signingAlias = signer;

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(level);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

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
        ASiCWithXAdESService service = getService();

        DSSDocument toBeSigned = getDocumentToSign();
        ASiCWithXAdESSignatureParameters params = getSignatureParameters();

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        toBeSigned = createDocumentCopy(toBeSigned);
        params = createSignatureParametersCopy(params);

        return service.signDocument(toBeSigned, params, signatureValue);
    }

    private DSSDocument createDocumentCopy(DSSDocument document) {
        return new InMemoryDocument(DSSUtils.toByteArray(document), document.getName(), document.getMimeType());
    }

    private ASiCWithXAdESSignatureParameters createSignatureParametersCopy(ASiCWithXAdESSignatureParameters signatureParameters) {
        ASiCWithXAdESSignatureParameters signatureParametersCopy = new ASiCWithXAdESSignatureParameters();
        signatureParametersCopy.setSigningCertificate(signatureParameters.getSigningCertificate());
        signatureParametersCopy.setCertificateChain(signatureParameters.getCertificateChain());
        signatureParametersCopy.setSignatureLevel(signatureParameters.getSignatureLevel());
        signatureParametersCopy.setSignaturePackaging(signatureParameters.getSignaturePackaging());
        signatureParametersCopy.bLevel().setSigningDate(signatureParameters.bLevel().getSigningDate());
        signatureParametersCopy.aSiC().setContainerType(signatureParameters.aSiC().getContainerType());
        return signatureParametersCopy;
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected ASiCWithXAdESService getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
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
