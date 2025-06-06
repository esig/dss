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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelERSCounterSignatureTest extends AbstractCAdESCounterSignatureTest {

    private CAdESService service;
    private DSSDocument signedDocument;

    private Date signingDate;

    @BeforeEach
    void init() throws Exception {
        service = new CAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        signedDocument = new InMemoryDocument(CAdESLevelERSCounterSignatureTest.class.getResourceAsStream(
                "/validation/evidence-record/C-E-ERS.p7m"));
        signingDate = new Date();
    }

    @Override
    protected DSSDocument sign() {
        return signedDocument;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        return getCounterSignatureParameters();
    }

    @Override
    protected CAdESCounterSignatureParameters getCounterSignatureParameters() {
        CAdESCounterSignatureParameters signatureParameters = new CAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return signedDocument;
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
        return GOOD_USER;
    }

    @Test
    @Override
    public void signAndVerify() {
        SignedDocumentValidator validator = getValidator(signedDocument);

        List<AdvancedSignature> signatures = validator.getSignatures();
        assertTrue(Utils.isCollectionNotEmpty(signatures));

        AdvancedSignature signature = signatures.get(0);
        String signatureId = signature.getId();

        Exception exception = assertThrows(IllegalInputException.class, () -> counterSign(signedDocument, signatureId));
        assertEquals("Cannot add a counter signature to a CMS containing an evidence record unsigned attribute.", exception.getMessage());
    }

}
