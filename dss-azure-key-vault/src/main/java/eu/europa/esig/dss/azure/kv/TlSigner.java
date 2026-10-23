package eu.europa.esig.dss.azure.kv;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import eu.europa.esig.dss.azure.kv.AzureCredentialProvider;

public class TlSigner {


    private final AzureKeyVaultSignatureTokenConnection token;
    private final XAdESService service;

    public TlSigner(String vaultUrl, String keyId, String certName, AzureCredentialProvider provider) {
        this.token = new AzureKeyVaultSignatureTokenConnection(vaultUrl, keyId, certName, provider.getCredential());
        this.service = new XAdESService(new CommonCertificateVerifier());
    }

    public void signTrustedList(Path inputPath, Path outputPath) throws Exception {
        byte[] xml = Files.readAllBytes(inputPath);
        DSSDocument doc = new InMemoryDocument(xml, inputPath.getFileName().toString(), MimeTypeEnum.XML);

        XAdESSignatureParameters params = new XAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);

        DSSPrivateKeyEntry keyEntry = token.getKeys().get(0);
        params.setSigningCertificate(keyEntry.getCertificate());
        params.setCertificateChain(keyEntry.getCertificateChain());

        ToBeSigned tbs = service.getDataToSign(doc, params);
        SignatureValue sig = token.sign(tbs, params.getDigestAlgorithm(), params.getSignatureAlgorithm());
        DSSDocument signed = service.signDocument(doc, params, sig);

        try (java.io.InputStream is = signed.openStream()) {
            Files.copy(is, outputPath, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("Trusted list signed and written to " + outputPath.toAbsolutePath());

        }
    }

}
