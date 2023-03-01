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
package eu.europa.esig.dss.asic.xades.merge.asice;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.merge.AbstractWithXAdESTestMerge;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.SimpleASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithXAdESLevelBContainerMergerWithCustomSignatureDocumentNameTest extends AbstractWithXAdESTestMerge {

    private List<DSSDocument> documentsToSignOne;
    private List<DSSDocument> documentsToSignTwo;

    private ASiCWithXAdESService service;

    private ASiCWithXAdESSignatureParameters firstSignatureParameters;
    private ASiCWithXAdESSignatureParameters secondSignatureParameters;

    @BeforeEach
    public void init() {
        documentsToSignOne = Arrays.asList(new FileDocument("src/test/resources/signable/test.txt"),
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeTypeEnum.TEXT));

        documentsToSignTwo = Arrays.asList(new FileDocument("src/test/resources/manifest-sample.xml"),
                new InMemoryDocument("Bye World!".getBytes(), "bye.txt", MimeTypeEnum.TEXT));

        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

        firstSignatureParameters = new ASiCWithXAdESSignatureParameters();
        firstSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        firstSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        firstSignatureParameters.bLevel().setSigningDate(new Date());

        secondSignatureParameters = new ASiCWithXAdESSignatureParameters();
        secondSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        secondSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        secondSignatureParameters.bLevel().setSigningDate(new Date());
    }

    @Override
    protected DSSDocument getFirstSignedContainer() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();
        filenameFactory.setSignatureFilename("signaturesAAA.xml");
        getService().setAsicFilenameFactory(filenameFactory);
        return super.getFirstSignedContainer();
    }

    @Override
    protected DSSDocument getSecondSignedContainer() {
        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();
        filenameFactory.setSignatureFilename("signaturesBBB.xml");
        getService().setAsicFilenameFactory(filenameFactory);
        return super.getSecondSignedContainer();
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        super.checkContainerInfo(diagnosticData);

        boolean firstSignatureNameFound = false;
        boolean secondSignatureNameFound = false;

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if ((ASiCUtils.META_INF_FOLDER + "signaturesAAA.xml")
                    .equals(signatureWrapper.getSignatureFilename())) {
                firstSignatureNameFound = true;
            } else if ((ASiCUtils.META_INF_FOLDER + "signaturesBBB.xml")
                    .equals(signatureWrapper.getSignatureFilename())) {
                secondSignatureNameFound = true;
            }
        }
        assertTrue(firstSignatureNameFound);
        assertTrue(secondSignatureNameFound);
    }

    @Override
    protected List<DSSDocument> getFirstSignedData() {
        return documentsToSignOne;
    }

    @Override
    protected List<DSSDocument> getSecondSignedData() {
        return documentsToSignTwo;
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
    protected ASiCWithXAdESService getService() {
        return service;
    }

}
