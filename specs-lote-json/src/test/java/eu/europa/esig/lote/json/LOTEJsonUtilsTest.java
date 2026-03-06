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
package eu.europa.esig.lote.json;

import eu.europa.esig.json.JSONParser;
import eu.europa.esig.json.JsonObjectWrapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LOTEJsonUtilsTest {

    @Test
    void validTest() {
        InputStream is = LOTEJsonUtilsTest.class.getResourceAsStream("/valid.json");
        JsonObjectWrapper jsonObject = new JSONParser().parse(is);

        assertNotNull(jsonObject);

        List<String> errors = LOTEJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void validTestFull() {
        InputStream is = LOTEJsonUtilsTest.class.getResourceAsStream("/valid-full.json");
        JsonObjectWrapper jsonObject = new JSONParser().parse(is);

        assertNotNull(jsonObject);

        List<String> errors = LOTEJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void mockPID() {
        InputStream is = LOTEJsonUtilsTest.class.getResourceAsStream("/Mock_PID_Provider_List_v0.0.2.json");
        JsonObjectWrapper jsonObject = new JSONParser().parse(is);

        assertNotNull(jsonObject);

        List<String> errors = LOTEJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void mockPIDOld() {
        InputStream is = LOTEJsonUtilsTest.class.getResourceAsStream("/Mock_PID_Provider_List_v0.0.1-fixed.json");
        JsonObjectWrapper jsonObject = new JSONParser().parse(is);

        assertNotNull(jsonObject);

        List<String> errors = LOTEJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void validTestEmptyTE() {
        InputStream is = LOTEJsonUtilsTest.class.getResourceAsStream("/valid-emptyTE.json");
        JsonObjectWrapper jsonObject = new JSONParser().parse(is);

        assertNotNull(jsonObject);

        List<String> errors = LOTEJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertTrue(errors.isEmpty(), errors.toString());
    }

    @Test
    void invalidTest() {
        InputStream is = LOTEJsonUtilsTest.class.getResourceAsStream("/invalid.json");
        JsonObjectWrapper jsonObject = new JSONParser().parse(is);

        assertNotNull(jsonObject);

        List<String> errors = LOTEJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertFalse(errors.isEmpty(), errors.toString());
    }

    @Test
    void emptySchemeExtensionsTest() {
        InputStream is = LOTEJsonUtilsTest.class.getResourceAsStream("/empty-only-schema-extensions.json");
        JsonObjectWrapper jsonObject = new JSONParser().parse(is);

        assertNotNull(jsonObject);

        List<String> errors = LOTEJsonUtils.getInstance().validateAgainstSchema(jsonObject);
        assertFalse(errors.isEmpty(), errors.toString());
    }

}
