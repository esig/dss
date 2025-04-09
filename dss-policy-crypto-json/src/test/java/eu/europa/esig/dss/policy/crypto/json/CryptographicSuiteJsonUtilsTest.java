package eu.europa.esig.dss.policy.crypto.json;

import com.github.erosb.jsonsKema.JsonObject;
import eu.europa.esig.json.JSONSchemaUtils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptographicSuiteJsonUtilsTest {

    @Test
    void validTest() throws Exception {
        JsonObject jsonObject = JSONSchemaUtils.getInstance().parseJson(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-fix.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

}
