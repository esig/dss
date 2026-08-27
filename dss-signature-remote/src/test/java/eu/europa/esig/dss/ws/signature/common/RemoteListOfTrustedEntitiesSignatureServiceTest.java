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
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteListOfTrustedEntitiesSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemoteListOfTrustedEntitiesSignatureServiceTest extends AbstractRemoteSignatureServiceTest {

    private RemoteListOfTrustedEntitiesSignatureServiceImpl service;

    private Date signingTime;

    @BeforeEach
    void init() {
        service = new RemoteListOfTrustedEntitiesSignatureServiceImpl();
        service.setXadesService(getXAdESService());
        service.setJadesService(getJAdESService());
        service.setCbadesService(getCBAdESService());

        signingTime = new Date();
    }

    @Test
    void jsonTest() {
        DSSDocument loteToSign = new FileDocument(new File("src/test/resources/lote.json"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(loteToSign), loteToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteListOfTrustedEntitiesSignatureParameters parameters = new RemoteListOfTrustedEntitiesSignatureParameters();
        parameters.setSigningCertificate(signingCertificate);

        ToBeSignedDTO dataToSign = service.getDataToSign(toSignDocument, parameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA512, getPrivateKeyEntry());
        RemoteDocument signedDocument = service.signDocument(toSignDocument, parameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        validate(iMD, SignatureLevel.JAdES_BASELINE_B);
    }

    @Test
    void xmlTest() {
        DSSDocument loteToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(loteToSign), loteToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteListOfTrustedEntitiesSignatureParameters parameters = new RemoteListOfTrustedEntitiesSignatureParameters();
        parameters.setSigningCertificate(signingCertificate);

        ToBeSignedDTO dataToSign = service.getDataToSign(toSignDocument, parameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA512, getPrivateKeyEntry());
        RemoteDocument signedDocument = service.signDocument(toSignDocument, parameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        validate(iMD, SignatureLevel.XAdES_BASELINE_B);
    }

    @Test
    void xmlWithCustomParametersTest() {
        DSSDocument loteToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(loteToSign), loteToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteListOfTrustedEntitiesSignatureParameters parameters = new RemoteListOfTrustedEntitiesSignatureParameters();
        parameters.setSigningCertificate(signingCertificate);
        parameters.setReferenceId("lote-xml");
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA512);

        RemoteBLevelParameters bLevelParams = new RemoteBLevelParameters();
        bLevelParams.setSigningDate(signingTime);
        parameters.setBLevelParameters(bLevelParams);

        ToBeSignedDTO dataToSign = service.getDataToSign(toSignDocument, parameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument signedDocument = service.signDocument(toSignDocument, parameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        DiagnosticData diagnosticData = validate(iMD, SignatureLevel.XAdES_BASELINE_B);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SignatureAlgorithm.RSA_SHA256, signature.getSignatureAlgorithm());

        boolean lotlRefFound = false;
        List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (digestMatcher.getId() != null && digestMatcher.getId().equals("lote-xml")) {
                assertEquals(DigestAlgorithm.SHA512, digestMatcher.getDigestMethod());
                lotlRefFound = true;
            }
        }
        assertTrue(lotlRefFound);
        assertEquals(DSSUtils.formatDateToRFC(signingTime), DSSUtils.formatDateToRFC(signature.getClaimedSigningTime()));
    }

    @Test
    void vicalTest() {
        DSSDocument loteToSign = new FileDocument(new File("src/test/resources/vical.cbor"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(loteToSign), loteToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteListOfTrustedEntitiesSignatureParameters parameters = new RemoteListOfTrustedEntitiesSignatureParameters();
        parameters.setSigningCertificate(signingCertificate);

        ToBeSignedDTO dataToSign = service.getDataToSign(toSignDocument, parameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA512, getPrivateKeyEntry());
        RemoteDocument signedDocument = service.signDocument(toSignDocument, parameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        validate(iMD, SignatureLevel.CB_AdES_BASELINE_B);
    }

    @Test
    void notSupportedFormatTest() {
        DSSDocument loteToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(loteToSign), loteToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteListOfTrustedEntitiesSignatureParameters parameters = new RemoteListOfTrustedEntitiesSignatureParameters();
        parameters.setSigningCertificate(signingCertificate);

        Exception exception = assertThrows(UnsupportedOperationException.class, () -> service.getDataToSign(toSignDocument, parameters));
        assertEquals("The document type is not supported!", exception.getMessage());

        exception = assertThrows(UnsupportedOperationException.class, () -> service.signDocument(toSignDocument, parameters,
                new SignatureValueDTO(SignatureAlgorithm.RSA_SHA512, new byte[] {})));
        assertEquals("The document type is not supported!", exception.getMessage());
    }

    protected DiagnosticData validate(DSSDocument doc, SignatureLevel expectedLevel) {
        DiagnosticData diagnosticData = super.validate(doc, null);

        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());
        assertEquals(expectedLevel, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));

        return diagnosticData;
    }

}
