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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

class ASiCEXAdESLevelBSignEnvelopedXAdESTest extends AbstractASiCEXAdESTestSignature {

    private DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithXAdESService(getOfflineCertificateVerifier());

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
    }

    @Override
    protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        if (documentToSign == null) {
            DSSDocument originalDocument = new FileDocument("src/test/resources/manifest-sample.xml");

            XAdESService xadesService = new XAdESService(getOfflineCertificateVerifier());
            XAdESSignatureParameters xadesSignatureParameters = new XAdESSignatureParameters();
            xadesSignatureParameters.setSigningCertificate(getSigningCert());
            xadesSignatureParameters.setCertificateChain(getCertificateChain());
            xadesSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            xadesSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);

            DSSReference reference = new DSSReference();
            reference.setContents(originalDocument);
            reference.setId("ref-id-1");
            reference.setUri("");
            reference.setTransforms(Arrays.asList(new EnvelopedSignatureTransform(), new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE)));
            xadesSignatureParameters.setReferences(Collections.singletonList(reference));

            ToBeSigned dataToSign = xadesService.getDataToSign(originalDocument, xadesSignatureParameters);
            SignatureValue signatureValue = getToken().sign(dataToSign, xadesSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
            documentToSign = xadesService.signDocument(originalDocument, xadesSignatureParameters, signatureValue);
        }
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
