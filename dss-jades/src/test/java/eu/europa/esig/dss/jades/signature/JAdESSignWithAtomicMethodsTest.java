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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
public class JAdESSignWithAtomicMethodsTest extends AbstractJAdESTestSignature {

    private static JAdESSignatureParameters signatureParameters;
    private static JAdESService service;
    private static CertificateVerifier certificateVerifier;

    private String signingAlias;
    private DSSDocument documentToSign;

    @BeforeAll
    public static void initAll() {
        certificateVerifier = new CommonCertificateVerifier();
        service = new JAdESService(certificateVerifier);
    }

    private static Stream<Arguments> data() {
        SignatureLevel[] levels = { SignatureLevel.JAdES_BASELINE_B, SignatureLevel.JAdES_BASELINE_T,
                SignatureLevel.JAdES_BASELINE_LT, SignatureLevel.JAdES_BASELINE_LTA };
        SignaturePackaging[] packagings = { SignaturePackaging.ENVELOPING, SignaturePackaging.DETACHED };
        String[] signers = { GOOD_USER, RSA_SHA3_USER };
        DSSDocument[] documents = { new FileDocument("src/test/resources/sample.json"),
                new FileDocument("src/test/resources/sample.png") };
        return random(levels, packagings, signers, documents);
    }

    static Stream<Arguments> random(SignatureLevel[] levels, SignaturePackaging[] packagings, String[] signers, DSSDocument[] documents) {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < levels.length; i++) {
            for (int j = 0; j < packagings.length; j++) {
                for (int m = 0; m < signers.length; m++) {
                    for (int n = 0; n < documents.length; n++) {
                        if (SignaturePackaging.DETACHED.equals(packagings[j])) {
                            args.add(Arguments.of(levels[i], packagings[j], SigDMechanism.NO_SIG_D, signers[m], documents[n]));
                            args.add(Arguments.of(levels[i], packagings[j], SigDMechanism.OBJECT_ID_BY_URI, signers[m], documents[n]));
                            args.add(Arguments.of(levels[i], packagings[j], SigDMechanism.OBJECT_ID_BY_URI_HASH, signers[m], documents[n]));
                        } else {
                            args.add(Arguments.of(levels[i], packagings[j], null, signers[m], documents[n]));
                        }
                    }
                }
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Sign JAdES {index} : {0} - {1} - {2} - {3} - {4}")
    @MethodSource("data")
    public void init(SignatureLevel level, SignaturePackaging packaging, SigDMechanism sigDMechanism,
                     String signer, DSSDocument document) {
        documentToSign = document;
        signingAlias = signer;

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(level);
        signatureParameters.setSignaturePackaging(packaging);
        signatureParameters.setSigDMechanism(sigDMechanism);
        signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

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
        JAdESService service = getService();

        DSSDocument toBeSigned = getDocumentToSign();
        JAdESSignatureParameters params = getSignatureParameters();

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(),
                getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        toBeSigned = createDocumentCopy(toBeSigned);
        params = createSignatureParametersCopy(params);

        return service.signDocument(toBeSigned, params, signatureValue);
    }

    private DSSDocument createDocumentCopy(DSSDocument document) {
        return new InMemoryDocument(DSSUtils.toByteArray(document), document.getName(), document.getMimeType());
    }

    private JAdESSignatureParameters createSignatureParametersCopy(JAdESSignatureParameters signatureParameters) {
        JAdESSignatureParameters signatureParametersCopy = new JAdESSignatureParameters();
        signatureParametersCopy.setSigningCertificate(signatureParameters.getSigningCertificate());
        signatureParametersCopy.setCertificateChain(signatureParameters.getCertificateChain());
        signatureParametersCopy.setSignatureLevel(signatureParameters.getSignatureLevel());
        signatureParametersCopy.setSignaturePackaging(signatureParameters.getSignaturePackaging());
        signatureParametersCopy.setSigDMechanism(signatureParameters.getSigDMechanism());
        signatureParametersCopy.setJwsSerializationType(signatureParameters.getJwsSerializationType());
        signatureParametersCopy.bLevel().setSigningDate(signatureParameters.bLevel().getSigningDate());
        return signatureParametersCopy;
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        if (SignaturePackaging.DETACHED.equals(signatureParameters.getSignaturePackaging())) {
            return Arrays.asList(getDocumentToSign());
        }
        return Collections.emptyList();
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected JAdESService getService() {
        return service;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
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
