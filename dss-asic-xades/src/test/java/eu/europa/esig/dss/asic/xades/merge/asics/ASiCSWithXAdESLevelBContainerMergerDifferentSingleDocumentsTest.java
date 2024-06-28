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
package eu.europa.esig.dss.asic.xades.merge.asics;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.merge.AbstractWithXAdESTestMerge;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCSWithXAdESLevelBContainerMergerDifferentSingleDocumentsTest extends AbstractWithXAdESTestMerge {

    private DSSDocument documentToSignOne;
    private DSSDocument documentToSignTwo;

    private ASiCWithXAdESService service;

    private ASiCWithXAdESSignatureParameters firstSignatureParameters;
    private ASiCWithXAdESSignatureParameters secondSignatureParameters;

    @BeforeEach
    void init() {
        documentToSignOne = new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeTypeEnum.TEXT);
        documentToSignTwo = new InMemoryDocument("Bye World!".getBytes(), "bye.txt", MimeTypeEnum.TEXT);

        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

        firstSignatureParameters = new ASiCWithXAdESSignatureParameters();
        firstSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        firstSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        firstSignatureParameters.bLevel().setSigningDate(new Date());

        secondSignatureParameters = new ASiCWithXAdESSignatureParameters();
        secondSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        secondSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        secondSignatureParameters.bLevel().setSigningDate(new Date());
    }

    @Test
    @Override
    public void createTwoContainersAndMerge() throws Exception {
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> super.createTwoContainersAndMerge());
        assertEquals("Unable to merge ASiC-S with XAdES containers. Signer documents have different names!", exception.getMessage());
    }

    @Override
    protected List<DSSDocument> getFirstSignedData() {
        return Collections.singletonList(documentToSignOne);
    }

    @Override
    protected List<DSSDocument> getSecondSignedData() {
        return Collections.singletonList(documentToSignTwo);
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getFirstSignatureParameters() {
        firstSignatureParameters.setSigningCertificate(getSigningCert());
        firstSignatureParameters.setCertificateChain(getCertificateChain());
        return firstSignatureParameters;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSecondSignatureParameters() {
        secondSignatureParameters.setSigningCertificate(getSigningCert());
        secondSignatureParameters.setCertificateChain(getCertificateChain());
        return secondSignatureParameters;
    }

    @Override
    protected String getFirstSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected String getSecondSigningAlias() {
        return RSA_SHA3_USER;
    }

    @Override
    protected MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

}
