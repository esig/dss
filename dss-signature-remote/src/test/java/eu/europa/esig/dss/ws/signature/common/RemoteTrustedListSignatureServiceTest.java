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
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTrustedListSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemoteTrustedListSignatureServiceTest extends AbstractRemoteSignatureServiceTest {

    private RemoteTrustedListSignatureServiceImpl tlSigningService;

    private Date signingTime;

    @BeforeEach
    void init() {
        tlSigningService = new RemoteTrustedListSignatureServiceImpl();
        tlSigningService.setXadesService(getXAdESService());

        signingTime = new Date();
    }

    @Test
    void test() {
        DSSDocument lotlToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(lotlToSign), lotlToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteTrustedListSignatureParameters tlSignatureParameters = new RemoteTrustedListSignatureParameters();
        tlSignatureParameters.setSigningCertificate(signingCertificate);
        tlSignatureParameters.setTlVersion("5");

        ToBeSignedDTO dataToSign = tlSigningService.getDataToSign(toSignDocument, tlSignatureParameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA512, getPrivateKeyEntry());
        RemoteDocument signedDocument = tlSigningService.signDocument(toSignDocument, tlSignatureParameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        validate(iMD, null);
    }

    @Test
    void testWithCustomParams() {
        DSSDocument lotlToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(lotlToSign), lotlToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteTrustedListSignatureParameters parameters = new RemoteTrustedListSignatureParameters();
        parameters.setSigningCertificate(signingCertificate);
        parameters.setReferenceId("lotl");
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA512);
        parameters.setTlVersion("5");

        RemoteBLevelParameters bLevelParams = new RemoteBLevelParameters();
        bLevelParams.setSigningDate(signingTime);
        parameters.setBLevelParameters(bLevelParams);

        ToBeSignedDTO dataToSign = tlSigningService.getDataToSign(toSignDocument, parameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument signedDocument = tlSigningService.signDocument(toSignDocument, parameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        DiagnosticData diagnosticData = validate(iMD, null);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SignatureAlgorithm.RSA_SHA256, signature.getSignatureAlgorithm());

        boolean lotlRefFound = false;
        List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (digestMatcher.getId() != null && digestMatcher.getId().equals("lotl")) {
                assertEquals(DigestAlgorithm.SHA512, digestMatcher.getDigestMethod());
                lotlRefFound = true;
            }
        }
        assertTrue(lotlRefFound);
    }

    @Test
    void testWithCustomSignatureAlgorithmParams() {
        DSSDocument lotlToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(lotlToSign), lotlToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteTrustedListSignatureParameters parameters = new RemoteTrustedListSignatureParameters();
        parameters.setSigningCertificate(signingCertificate);
        parameters.setReferenceId("lotl");
        parameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setTlVersion("5");

        parameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

        RemoteBLevelParameters bLevelParams = new RemoteBLevelParameters();
        bLevelParams.setSigningDate(signingTime);
        parameters.setBLevelParameters(bLevelParams);

        ToBeSignedDTO dataToSign = tlSigningService.getDataToSign(toSignDocument, parameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, getPrivateKeyEntry());
        RemoteDocument signedDocument = tlSigningService.signDocument(toSignDocument, parameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        DiagnosticData diagnosticData = validate(iMD, null);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, signature.getSignatureAlgorithm());

        boolean lotlRefFound = false;
        List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (digestMatcher.getId() != null && digestMatcher.getId().equals("lotl")) {
                assertEquals(DigestAlgorithm.SHA256, digestMatcher.getDigestMethod());
                lotlRefFound = true;
            }
        }
        assertTrue(lotlRefFound);
    }

    @Test
    void testTLV6() {
        DSSDocument lotlToSign = new FileDocument(new File("src/test/resources/trusted-list-v6.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(lotlToSign), lotlToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteTrustedListSignatureParameters tlSignatureParameters = new RemoteTrustedListSignatureParameters();
        tlSignatureParameters.setSigningCertificate(signingCertificate);
        tlSignatureParameters.setTlVersion("5");

        Exception exception = assertThrows(IllegalInputException.class, () -> tlSigningService.getDataToSign(toSignDocument, tlSignatureParameters));
        assertEquals("XML Trusted List failed the validation : TSL Version '6' found in the XML Trusted List " +
                "does not correspond to the target version defined by the builder '5'! " +
                "Please modify the document or change to the appropriate builder.", exception.getMessage());

        tlSignatureParameters.setTlVersion("6");

        ToBeSignedDTO dataToSign = tlSigningService.getDataToSign(toSignDocument, tlSignatureParameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA512, getPrivateKeyEntry());
        RemoteDocument signedDocument = tlSigningService.signDocument(toSignDocument, tlSignatureParameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        validate(iMD, null);
    }

    @Test
    void testInvalidTlVersion() {
        DSSDocument lotlToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(lotlToSign), lotlToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteTrustedListSignatureParameters tlSignatureParameters = new RemoteTrustedListSignatureParameters();
        tlSignatureParameters.setSigningCertificate(signingCertificate);
        tlSignatureParameters.setTlVersion("five");

        Exception exception = assertThrows(DSSRemoteServiceException.class, () -> tlSigningService.getDataToSign(toSignDocument, tlSignatureParameters));
        assertEquals("The TlVersion parameter shall be represented by a valid integer! Obtained value 'five'.", exception.getMessage());

        tlSignatureParameters.setTlVersion("1234564878912356489481548465141568464");

        exception = assertThrows(DSSRemoteServiceException.class, () -> tlSigningService.getDataToSign(toSignDocument, tlSignatureParameters));
        assertEquals("The TlVersion parameter shall be represented by a valid integer! Obtained value '1234564878912356489481548465141568464'.", exception.getMessage());

        tlSignatureParameters.setTlVersion("7");

        exception = assertThrows(DSSRemoteServiceException.class, () -> tlSigningService.getDataToSign(toSignDocument, tlSignatureParameters));
        assertEquals("Unsupported TLVersionIdentifier '7'!", exception.getMessage());
    }

}
