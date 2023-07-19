package pkifactory.business;

import eu.europa.esig.dss.pki.service.KeyPairBuilder;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class KeyPairBuilderTest {

    @Test
    public void rsa1024() throws GeneralSecurityException {
        KeyPairBuilder builder = new KeyPairBuilder();
        builder.encryptionAlgo("RSA");
        builder.keySize(1024);
        KeyPair kp = builder.build();
        assertNotNull(kp);
    }

    @Test
    public void rsa2048() throws GeneralSecurityException {
        assertNotNull(KeyPairBuilder.rsa2048());
    }

}
