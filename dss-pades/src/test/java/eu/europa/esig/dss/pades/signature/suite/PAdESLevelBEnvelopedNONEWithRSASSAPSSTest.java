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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class PAdESLevelBEnvelopedNONEWithRSASSAPSSTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
            if (SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSASSA_PSS, digestAlgorithm) != null) {
                args.add(Arguments.of(digestAlgorithm));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Combination {index} of RSASSA-PSS and digest algorithm {0}")
    @MethodSource("data")
    public void init(DigestAlgorithm digestAlgo) {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(digestAlgo);
        signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);

        service = new PAdESService(getOfflineCertificateVerifier());

        super.signAndVerify();
    }

    @Override
    public void signAndVerify() {
    }

    @Override
    protected DSSDocument sign() {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);

        byte[] originalDigest = DSSUtils.digest(signatureParameters.getDigestAlgorithm(), dataToSign.getBytes());
        Digest digest = new Digest(signatureParameters.getDigestAlgorithm(), originalDigest);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSASSA_PSS, signatureParameters.getDigestAlgorithm());
        SignatureValue signatureValue = getToken().signDigest(digest, signatureAlgorithm, getPrivateKeyEntry());
        return service.signDocument(documentToSign, signatureParameters, signatureValue);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}
