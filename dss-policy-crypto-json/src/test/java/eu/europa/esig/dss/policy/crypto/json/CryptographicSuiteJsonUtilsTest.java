package eu.europa.esig.dss.policy.crypto.json;

import com.github.erosb.jsonsKema.JsonObject;
import eu.europa.esig.json.JSONParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptographicSuiteJsonUtilsTest {

    @Test
    void validTest() {
        JsonObject jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-fix.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void invalidTest() {
        // TODO : the original JSON schema fails validation
        JsonObject jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable.json"));
        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertFalse(errors.isEmpty(), errors.toString());
    }

    @Test
    void signedCompactJWSTest() {
        JsonObject jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-signed-compact-jws.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void signedFlattenedJWSTest() {
        JsonObject jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-signed-flattened-jws.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void signedInvalidTypeTest() {
        // TODO : design choice is to allow any signature type, as not explicitly defined in the standard
        JsonObject jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-invalid-signature-type.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
        // TODO : in case restricting to JWS signatures only
        // assertFalse(errors.isEmpty());
        // assertTrue(errors.stream().anyMatch(e -> e.contains("Signature")));
    }

}
