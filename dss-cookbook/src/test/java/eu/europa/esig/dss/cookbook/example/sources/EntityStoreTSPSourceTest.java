package eu.europa.esig.dss.cookbook.example.sources;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Date;

public class EntityStoreTSPSourceTest {

    @Test
    public void test() throws Exception {
        String keyStoreFileName = "src/main/resources/user_a_rsa.p12";
        char[] keyStorePassword = "password".toCharArray();

        // tag::demo[]
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
        // import eu.europa.esig.dss.spi.x509.tsp.KeyStoreTSPSource;
        // import java.io.File;
        // import java.nio.file.Files;
        // import java.security.KeyStore;
        // import java.util.Arrays;
        // import java.util.Date;
        File keyStoreFile = new File(keyStoreFileName);

        // instantiate the KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(Files.newInputStream(keyStoreFile.toPath()), keyStorePassword);

        // instantiate the KeyStoreTSPSource
        KeyEntityTSPSource entityStoreTSPSource = new KeyEntityTSPSource(keyStore, "certificate", keyStorePassword);

        // This method allows configuration of digest algorithms to be supported for a timestamp request
        // Default: SHA-224, SHA-256, SHA-384, SHA-512
        entityStoreTSPSource.setAcceptedDigestAlgorithms(Arrays.asList(
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512));

        // This method allows definition of a timestamping policy
        // Default: a dummy TSA policy "1.2.3.4" is used
        entityStoreTSPSource.setTsaPolicy("1.2.3.4");

        // This method allows definition of a custom production time of the timestamp
        // Default: the current time is used
        entityStoreTSPSource.setProductionTime(new Date());

        // This method allows definition of a digest algorithm to be used for a signature of the generated time-stamp
        // Default: SHA-256
        entityStoreTSPSource.setDigestAlgorithm(DigestAlgorithm.SHA256);

        // This method defines a Mask Generation Function to be used on signing
        // Default: NONE (no PSS is used)
        entityStoreTSPSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);
        // end::demo[]

    }

}
