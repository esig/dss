package eu.europa.esig.dss.pki.jaxb.service;

import eu.europa.esig.dss.pki.jaxb.XmlEncryptionAlgo;
import eu.europa.esig.dss.pki.jaxb.XmlKeyAlgo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

public class KeyPairBuilder {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private String encryptionAlgo;
    private Integer keySize;

    public static KeyPair build(XmlKeyAlgo algo) throws GeneralSecurityException {
        KeyPairBuilder kpb = new KeyPairBuilder();
        kpb.encryptionAlgo = algo.getEncryption().value();
        kpb.keySize = algo.getLength();
        return kpb.build();
    }

    public static KeyPair rsa2048() throws GeneralSecurityException {
        KeyPairBuilder kpb = new KeyPairBuilder();
        kpb.encryptionAlgo("RSA");
        kpb.keySize(2048);
        return kpb.build();
    }

    public KeyPairBuilder encryptionAlgo(String encryptionAlgo) {
        this.encryptionAlgo = encryptionAlgo;
        return this;
    }

    public KeyPairBuilder keySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    public KeyPair build() throws GeneralSecurityException {
        if (XmlEncryptionAlgo.ECDSA.value().equals(encryptionAlgo)) {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(getEllipticCurveName());
            KeyPairGenerator generator = KeyPairGenerator.getInstance(encryptionAlgo, BouncyCastleProvider.PROVIDER_NAME);
            generator.initialize(ecSpec, new SecureRandom());
            return generator.generateKeyPair();
        } else {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(encryptionAlgo, BouncyCastleProvider.PROVIDER_NAME);
            if (keySize != null) {
                keyGenerator.initialize(keySize);
            }
            return keyGenerator.generateKeyPair();
        }
    }

    private String getEllipticCurveName() {
        if (keySize != null) {
            return String.format("secp%sr1", keySize);
        } else {
            return "prime256v1";
        }
    }

}
