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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
public class JAdESLevelBWithPlainECDSATokenTest extends AbstractJAdESTestSignature {

    private static final String HELLO_WORLD = "Hello World";

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private JAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static Stream<DigestAlgorithm> data() {
        List<DigestAlgorithm> args = new ArrayList<>();

        for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
            SignatureAlgorithm ecCa = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, digestAlgo);
            SignatureAlgorithm plainEcCa = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, digestAlgo);
            if (ecCa != null && Utils.isStringNotBlank(ecCa.getJWAId()) && plainEcCa != null && Utils.isStringNotBlank(plainEcCa.getJWAId())) {
                args.add(digestAlgo);
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Combination {index} of ECDSA with {0}")
    @MethodSource("data")
    public void init(DigestAlgorithm digestAlgo) {
        documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(digestAlgo);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.ECDSA);

        service = new JAdESService(getOfflineCertificateVerifier());

        super.signAndVerify();
    }

    @Override
    protected DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

        // simulate a token returning PLAIN_ECDSA
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, signatureParameters.getDigestAlgorithm());
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureAlgorithm, getPrivateKeyEntry());
        assertEquals(signatureAlgorithm, signatureValue.getAlgorithm());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        return service.signDocument(documentToSign, signatureParameters, signatureValue);
    }

    @Override
    protected void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
        assertEquals(EncryptionAlgorithm.ECDSA, diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId())
                .getEncryptionAlgorithm());
    }

    @Override
    public void signAndVerify() {
    }

    @Override
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
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
        return ECDSA_USER;
    }

}
