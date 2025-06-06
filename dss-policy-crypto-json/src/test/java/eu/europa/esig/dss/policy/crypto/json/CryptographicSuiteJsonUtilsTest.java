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
package eu.europa.esig.dss.policy.crypto.json;

import eu.europa.esig.json.JSONParser;
import eu.europa.esig.json.JsonObjectWrapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptographicSuiteJsonUtilsTest {

    @Test
    void validTest() {
        JsonObjectWrapper jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-fix.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void invalidTest() {
        // TODO : the original JSON schema fails validation
        JsonObjectWrapper jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable.json"));
        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertFalse(errors.isEmpty(), errors.toString());
    }

    @Test
    void signedCompactJWSTest() {
        JsonObjectWrapper jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-signed-compact-jws.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void signedFlattenedJWSTest() {
        JsonObjectWrapper jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-signed-flattened-jws.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void signedInvalidTypeTest() {
        // TODO : design choice is to allow any signature type, as not explicitly defined in the standard
        JsonObjectWrapper jsonObject = new JSONParser().parse(
                CryptographicSuiteJsonUtilsTest.class.getResourceAsStream("/19312MachineReadable-invalid-signature-type.json"));

        List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
        // TODO : in case restricting to JWS signatures only
        // assertFalse(errors.isEmpty());
        // assertTrue(errors.stream().anyMatch(e -> e.contains("Signature")));
    }

}
