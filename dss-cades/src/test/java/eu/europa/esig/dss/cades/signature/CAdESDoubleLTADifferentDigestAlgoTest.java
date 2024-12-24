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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESDoubleLTADifferentDigestAlgoTest extends AbstractCAdESTestSignature {

    private static final DSSDocument ORIGINAL_DOC = new InMemoryDocument("Hello World".getBytes());

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        CAdESTimestampParameters archiveTimeStampParameters = new CAdESTimestampParameters();
        archiveTimeStampParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        signatureParameters.setArchiveTimestampParameters(archiveTimeStampParameters);

        service = new CAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = ORIGINAL_DOC;
        DSSDocument signedDocument = super.sign();

        documentToSign = signedDocument;
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA224);

        CAdESTimestampParameters archiveTimeStampParameters = new CAdESTimestampParameters();
        archiveTimeStampParameters.setDigestAlgorithm(DigestAlgorithm.SHA384);
        signatureParameters.setArchiveTimestampParameters(archiveTimeStampParameters);

        DSSDocument doubleSignedDocument = super.sign();

        documentToSign = ORIGINAL_DOC;
        return doubleSignedDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        assertEquals(2, signatures.size());
        // both signatures refer the same set of Digest Algos
        for (AdvancedSignature signature : signatures) {
            CAdESSignature cadesSignature = (CAdESSignature) signature;
            Set<DigestAlgorithm> messageDigestAlgorithms = cadesSignature.getMessageDigestAlgorithms();
            assertEquals(4, messageDigestAlgorithms.size());

            boolean sha224Found = false;
            boolean sha256Found = false;
            boolean sha384Found = false;
            boolean sha512Found = false;
            for (DigestAlgorithm digestAlgorithm : messageDigestAlgorithms) {
                if (DigestAlgorithm.SHA224.equals(digestAlgorithm)) {
                    sha224Found = true;
                } else if (DigestAlgorithm.SHA256.equals(digestAlgorithm)) {
                    sha256Found = true;
                } else if (DigestAlgorithm.SHA384.equals(digestAlgorithm)) {
                    sha384Found = true;
                } else if (DigestAlgorithm.SHA512.equals(digestAlgorithm)) {
                    sha512Found = true;
                }
            }
            assertTrue(sha224Found);
            assertTrue(sha256Found);
            assertTrue(sha384Found);
            assertTrue(sha512Found);
        }
    }

    @Override
    protected void checkArchiveTimeStampV3(byte[] byteArray) {
        // skip (digestAlgo change)
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
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
