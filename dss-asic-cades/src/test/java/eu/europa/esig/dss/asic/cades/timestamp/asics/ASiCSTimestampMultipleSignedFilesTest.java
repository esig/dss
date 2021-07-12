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
package eu.europa.esig.dss.asic.cades.timestamp.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.signature.AbstractASiCWithCAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ASiCSTimestampMultipleSignedFilesTest extends AbstractASiCWithCAdESMultipleDocumentsTestSignature {

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentsToSign;

    @BeforeEach
    public void init() throws Exception {
        service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
        DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT);
        documentsToSign = Arrays.asList(documentToSign, documentToSign2);

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
    }

    @Test
    public void test() {
        DSSDocument signedDocument = super.sign();

        ASiCWithCAdESTimestampParameters timestampParameters = new ASiCWithCAdESTimestampParameters();
        timestampParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        Exception exception = assertThrows(IllegalInputException.class, () -> service.timestamp(signedDocument, timestampParameters));
        assertEquals("Unable to timestamp an ASiC-S with CAdES container containing signature files! " +
                "Use extendDocument(...) method for signature extension.", exception.getMessage());
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentsToSign;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeType.ASICS;
    }

    @Override
    protected boolean isBaselineT() {
        return false;
    }

    @Override
    protected boolean isBaselineLTA() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
