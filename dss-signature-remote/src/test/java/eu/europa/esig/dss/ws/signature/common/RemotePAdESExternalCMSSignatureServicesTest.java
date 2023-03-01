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
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.ColorConverter;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageTextParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class RemotePAdESExternalCMSSignatureServicesTest extends AbstractRemoteSignatureServiceTest {

    private RemotePAdESWithExternalCMSServiceImpl padesWithExternalCMSService;
    private RemoteExternalCMSServiceImpl externalCMSService;

    @BeforeEach
    public void init() {
        padesWithExternalCMSService = new RemotePAdESWithExternalCMSServiceImpl();
        padesWithExternalCMSService.setService(getPAdESWithExternalCMSService());

        externalCMSService = new RemoteExternalCMSServiceImpl();
        externalCMSService.setService(getExternalCMSService());
    }

    private PAdESWithExternalCMSService getPAdESWithExternalCMSService() {
        PAdESWithExternalCMSService padesWithExternalCMSService = new PAdESWithExternalCMSService();
        padesWithExternalCMSService.setCertificateVerifier(getCompleteCertificateVerifier());
        padesWithExternalCMSService.setTspSource(getGoodTsa());
        return padesWithExternalCMSService;
    }

    private ExternalCMSService getExternalCMSService() {
        ExternalCMSService externalCMSService = new ExternalCMSService(getOfflineCertificateVerifier());
        externalCMSService.setTspSource(getGoodTsa());
        return externalCMSService;
    }

    @Test
    public void testBLevelSign() throws Exception {
        RemoteSignatureParameters padesParameters = new RemoteSignatureParameters();
        padesParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
        DigestDTO messageDigest = padesWithExternalCMSService.getMessageDigest(toSignDocument, padesParameters);

        RemoteSignatureParameters cmsParameters = new RemoteSignatureParameters();
        cmsParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        cmsParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));

        ToBeSignedDTO dataToSign = externalCMSService.getDataToSign(messageDigest, cmsParameters);
        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument cmsSignature = externalCMSService.signMessageDigest(messageDigest, cmsParameters,
                DTOConverter.toSignatureValueDTO(signatureValue));
        assertNotNull(cmsSignature);

        RemoteDocument signedDocument = padesWithExternalCMSService.signDocument(toSignDocument, padesParameters, cmsSignature);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        DiagnosticData diagnosticData = validate(iMD, null);
        assertEquals(SignatureLevel.PAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Test
    public void testTLevelSign() throws Exception {
        RemoteSignatureParameters padesParameters = new RemoteSignatureParameters();
        padesParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
        DigestDTO messageDigest = padesWithExternalCMSService.getMessageDigest(toSignDocument, padesParameters);

        RemoteSignatureParameters cmsParameters = new RemoteSignatureParameters();
        cmsParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        cmsParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));

        ToBeSignedDTO dataToSign = externalCMSService.getDataToSign(messageDigest, cmsParameters);
        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument cmsSignature = externalCMSService.signMessageDigest(messageDigest, cmsParameters,
                DTOConverter.toSignatureValueDTO(signatureValue));
        assertNotNull(cmsSignature);

        RemoteDocument signedDocument = padesWithExternalCMSService.signDocument(toSignDocument, padesParameters, cmsSignature);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        DiagnosticData diagnosticData = validate(iMD, null);
        assertEquals(SignatureLevel.PAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Test
    public void testCMSTLevelSign() throws Exception {
        RemoteSignatureParameters padesParameters = new RemoteSignatureParameters();
        padesParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
        DigestDTO messageDigest = padesWithExternalCMSService.getMessageDigest(toSignDocument, padesParameters);

        RemoteSignatureParameters cmsParameters = new RemoteSignatureParameters();
        cmsParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        cmsParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));

        ToBeSignedDTO dataToSign = externalCMSService.getDataToSign(messageDigest, cmsParameters);
        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument cmsSignature = externalCMSService.signMessageDigest(messageDigest, cmsParameters,
                DTOConverter.toSignatureValueDTO(signatureValue));
        assertNotNull(cmsSignature);

        RemoteDocument signedDocument = padesWithExternalCMSService.signDocument(toSignDocument, padesParameters, cmsSignature);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        DiagnosticData diagnosticData = validate(iMD, null);
        assertEquals(SignatureLevel.PAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Test
    public void testCMSLTALevelSign() throws Exception {
        RemoteSignatureParameters padesParameters = new RemoteSignatureParameters();
        padesParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
        DigestDTO messageDigest = padesWithExternalCMSService.getMessageDigest(toSignDocument, padesParameters);

        RemoteSignatureParameters cmsParameters = new RemoteSignatureParameters();
        cmsParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        cmsParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));

        ToBeSignedDTO dataToSign = externalCMSService.getDataToSign(messageDigest, cmsParameters);
        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument cmsSignature = externalCMSService.signMessageDigest(messageDigest, cmsParameters,
                DTOConverter.toSignatureValueDTO(signatureValue));
        assertNotNull(cmsSignature);

        RemoteDocument signedDocument = padesWithExternalCMSService.signDocument(toSignDocument, padesParameters, cmsSignature);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        DiagnosticData diagnosticData = validate(iMD, null);
        assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Test
    public void testBLevelWithVisualSignature() throws Exception {
        RemoteSignatureParameters padesParameters = new RemoteSignatureParameters();
        padesParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        RemoteSignatureImageParameters imageParameters = new RemoteSignatureImageParameters();
        RemoteSignatureImageTextParameters textParameters = new RemoteSignatureImageTextParameters();
        textParameters.setText("My signature");
        textParameters.setTextColor(ColorConverter.toRemoteColor(Color.GREEN));
        imageParameters.setTextParameters(textParameters);
        padesParameters.setImageParameters(imageParameters);

        FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
        DigestDTO messageDigest = padesWithExternalCMSService.getMessageDigest(toSignDocument, padesParameters);

        RemoteSignatureParameters cmsParameters = new RemoteSignatureParameters();
        cmsParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        cmsParameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));

        ToBeSignedDTO dataToSign = externalCMSService.getDataToSign(messageDigest, cmsParameters);
        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument cmsSignature = externalCMSService.signMessageDigest(messageDigest, cmsParameters,
                DTOConverter.toSignatureValueDTO(signatureValue));
        assertNotNull(cmsSignature);

        RemoteDocument signedDocument = padesWithExternalCMSService.signDocument(toSignDocument, padesParameters, cmsSignature);
        assertNotNull(signedDocument);

        InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        // iMD.save("target/signedDocument.pdf");
        DiagnosticData diagnosticData = validate(iMD, null);
        assertEquals(SignatureLevel.PAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}
