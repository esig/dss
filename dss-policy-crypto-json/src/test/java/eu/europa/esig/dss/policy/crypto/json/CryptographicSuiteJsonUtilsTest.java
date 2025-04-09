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

}
