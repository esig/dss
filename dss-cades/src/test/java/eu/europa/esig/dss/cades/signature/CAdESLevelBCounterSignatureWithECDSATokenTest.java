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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("slow")
class CAdESLevelBCounterSignatureWithECDSATokenTest extends AbstractCAdESCounterSignatureTest {

    private CAdESService service;
    private DSSDocument documentToSign;

    CAdESSignatureParameters signatureParameters;
    CAdESCounterSignatureParameters counterSignatureParameters;

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();

        for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
            if (isAcceptableDigestAlgo(digestAlgo)) {
                for (DigestAlgorithm messageDigest : DigestAlgorithm.values()) {
                    if (isAcceptableDigestAlgo(messageDigest)) {
                        args.add(Arguments.of(digestAlgo, messageDigest));
                    }
                }
            }
        }
        return args.stream();
    }

    private static boolean isAcceptableDigestAlgo(DigestAlgorithm digestAlgo) {
        SignatureAlgorithm ecCa = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, digestAlgo);
        SignatureAlgorithm plainEcCa = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, digestAlgo);
        return ecCa != null && Utils.isStringNotBlank(ecCa.getOid()) && plainEcCa != null && Utils.isStringNotBlank(plainEcCa.getOid());
    }

    @ParameterizedTest(name = "Combination {index} of signature with digestAlgorithm {0} and counter-signature PLAIN-ECDSA with {1}")
    @MethodSource("data")
    void init(DigestAlgorithm digestAlgo, DigestAlgorithm counterSignatureDigestAlgo) {
        documentToSign = new InMemoryDocument("Hello World".getBytes());

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(digestAlgo);

        counterSignatureParameters = new CAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(new Date());
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        counterSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        counterSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        counterSignatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA);
        counterSignatureParameters.setDigestAlgorithm(counterSignatureDigestAlgo);

        service = new CAdESService(getOfflineCertificateVerifier());

        super.signAndVerify();
    }

    @Override
    protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
        counterSignatureParameters.setSignatureIdToCounterSign(signatureId);

        // simulate a token returning ECDSA
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, counterSignatureParameters.getDigestAlgorithm());
        ToBeSigned dataToSign = service.getDataToBeCounterSigned(signatureDocument, counterSignatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureAlgorithm, getPrivateKeyEntry());
        return service.counterSignSignature(signatureDocument, counterSignatureParameters, signatureValue);
    }

    @Override
    protected void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getAllCounterSignatures()) {
            assertEquals(EncryptionAlgorithm.PLAIN_ECDSA, signatureWrapper.getEncryptionAlgorithm());
        }
    }

    @Override
    public void signAndVerify() {
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
        return counterSignatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<CAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
