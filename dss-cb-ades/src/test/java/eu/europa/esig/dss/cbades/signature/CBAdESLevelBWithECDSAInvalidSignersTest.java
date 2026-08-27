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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("slow")
class CBAdESLevelBWithECDSAInvalidSignersTest extends AbstractCBAdESTestSignature {

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private CBAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();

        for (COSEStructureType coseStructureType : COSEStructureType.values()) {
            for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
                SignatureAlgorithm sa = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, digestAlgo);
                if (sa != null && sa.getCOSEId() != null) {
                    for (String signer : getSigners(digestAlgo)) {
                        args.add(Arguments.of(coseStructureType, digestAlgo, signer));
                    }
                }
            }
        }

        return args.stream();
    }

    private static List<String> getSigners(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA256:
                return Arrays.asList(ECDSA_384_USER, ECDSA_521_USER);
            case SHA384:
                return Arrays.asList(ECDSA_USER, ECDSA_521_USER);
            case SHA512:
                return Arrays.asList(ECDSA_USER, ECDSA_384_USER);
            default:
                throw new UnsupportedOperationException(String.format(
                        "DigestAlgorithm '%s' is not supported!", digestAlgorithm));
        }
    }

    @ParameterizedTest(name = "Combination {index} if type {0} and ECDSA with digest algorithm {1} and signer {2}")
    @MethodSource("data")
    void init(COSEStructureType coseStructureType, DigestAlgorithm digestAlgo, String signingAlias) {
        this.signingAlias = signingAlias;

        documentToSign = new InMemoryDocument("Hello World!".getBytes(), "doc.txt");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setCoseStructureType(coseStructureType);
        signatureParameters.setDigestAlgorithm(digestAlgo);

        service = new CBAdESService(getOfflineCertificateVerifier());

        Exception exception = assertThrows(IllegalArgumentException.class, super::signAndVerify);
        assertEquals(String.format("For ECDSA with %s a key with P-%s curve shall be used for a COSE! See RFC 9053.",
                digestAlgo.getName(), getKeySizeForDigestAlgo(digestAlgo)), exception.getMessage());
    }

    private String getKeySizeForDigestAlgo(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA256:
                return "256";
            case SHA384:
                return "384";
            case SHA512:
                return "521";
            default:
                fail("Unsupported DigestAlgorithm : " + digestAlgorithm);
        }
        return null;
    }

    @Override
    public void signAndVerify() {
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
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