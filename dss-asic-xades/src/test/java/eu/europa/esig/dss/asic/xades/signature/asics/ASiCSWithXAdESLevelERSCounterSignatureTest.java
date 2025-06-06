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
package eu.europa.esig.dss.asic.xades.signature.asics;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.AbstractASiCXAdESCounterSignatureTest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithXAdESLevelERSCounterSignatureTest extends AbstractASiCXAdESCounterSignatureTest {

    private ASiCWithXAdESService service;
    private DSSDocument signedDocument;

    private Date signingDate;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithXAdESService(getOfflineCertificateVerifier());
        signedDocument = new FileDocument(new File("src/test/resources/validation/evidencerecord/asic-xades-ers.scs"));
        signingDate = new Date();
    }

    @Override
    protected DSSDocument sign() {
        return signedDocument;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return new ASiCWithXAdESSignatureParameters();
    }

    @Override
    protected XAdESCounterSignatureParameters getCounterSignatureParameters() {
        XAdESCounterSignatureParameters signatureParameters = new XAdESCounterSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return signedDocument;
    }

    @Override
    protected ASiCWithXAdESService getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<XAdESCounterSignatureParameters> getCounterSignatureService() {
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
        assertEquals("Signature extension is not possible. " +
                "The signature already contains en embedded evidence record.", exception.getMessage());
    }

}
