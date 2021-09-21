package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
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
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTrustedListSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class RemoteTrustedListSignatureServiceTest extends AbstractRemoteSignatureServiceTest {

    private RemoteTrustedListSignatureServiceImpl tlSigningService;

    private Date signingTime;

    @BeforeEach
    public void init() {
        tlSigningService = new RemoteTrustedListSignatureServiceImpl();
        tlSigningService.setXadesService(getXAdESService());

        signingTime = new Date();
    }

    @Test
    public void test() {
        DSSDocument lotlToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(lotlToSign), lotlToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteTrustedListSignatureParameters tlSignatureParameters = new RemoteTrustedListSignatureParameters();
        tlSignatureParameters.setSigningCertificate(signingCertificate);

        ToBeSignedDTO dataToSign = tlSigningService.getDataToSign(toSignDocument, tlSignatureParameters);
        assertNotNull(dataToSign);

        SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
        RemoteDocument signedDocument = tlSigningService.signDocument(toSignDocument, tlSignatureParameters,
                new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
        assertNotNull(signedDocument);

        DSSDocument iMD = new InMemoryDocument(signedDocument.getBytes());
        validate(iMD, null);
    }

    @Test
    public void testWithCustomParams() {
        DSSDocument lotlToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(lotlToSign), lotlToSign.getName());

        RemoteCertificate signingCertificate = RemoteCertificateConverter.toRemoteCertificate(getSigningCert());

        RemoteTrustedListSignatureParameters parameters = new RemoteTrustedListSignatureParameters();
        parameters.setSigningCertificate(signingCertificate);
        parameters.setReferenceId("lotl");
        parameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA512);

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
        validate(iMD, null);
    }

}
