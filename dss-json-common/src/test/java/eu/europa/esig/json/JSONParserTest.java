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
package eu.europa.esig.json;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JSONParserTest {

    @Test
    void parseTest() {
        JsonObjectWrapper jsonObject = new JSONParser().parse(new File("src/test/resources/sample.json"));
        assertNotNull(jsonObject);

        assertEquals("John", jsonObject.getAsString("name"));
        assertNull(jsonObject.getAsNumber("name"));
        assertNull(jsonObject.getAsObject("name"));
        assertEquals(Collections.emptyList(), jsonObject.getAsObjectList("name"));
        assertEquals(Collections.emptyList(), jsonObject.getAsStringList("name"));

        assertEquals(30, jsonObject.getAsNumber("age"));
        assertNull(jsonObject.getAsString("age"));
        assertNull(jsonObject.getAsObject("age"));
        assertEquals(Collections.emptyList(), jsonObject.getAsObjectList("age"));
        assertEquals(Collections.emptyList(), jsonObject.getAsStringList("age"));

        assertNull(jsonObject.getAsNumber("car"));
        assertNull(jsonObject.getAsString("car"));
        assertNull(jsonObject.getAsObject("car"));
        assertEquals(Collections.emptyList(), jsonObject.getAsObjectList("car"));
        assertEquals(Collections.emptyList(), jsonObject.getAsStringList("car"));

        assertNull(jsonObject.getAsNumber("address"));
        assertNull(jsonObject.getAsString("address"));
        assertNotNull(jsonObject.getAsObject("address"));
        assertEquals(Collections.emptyList(), jsonObject.getAsObjectList("address"));
        assertEquals(Collections.emptyList(), jsonObject.getAsStringList("address"));

        JsonObjectWrapper address = jsonObject.getAsObject("address");
        assertEquals("LU", address.getAsString("country"));

        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.set(1990, Calendar.JANUARY, 1);

        assertEquals("1990-01-01", jsonObject.getAsString("birthdate"));
        assertNull(jsonObject.getAsNumber("birthdate"));
        assertNull(jsonObject.getAsObject("birthdate"));
        assertEquals(Collections.emptyList(), jsonObject.getAsObjectList("birthdate"));
        assertEquals(Collections.emptyList(), jsonObject.getAsStringList("birthdate"));

        assertEquals(2, jsonObject.getAsObjectList("parents").size());
        assertEquals(0, jsonObject.getAsStringList("parents").size());
        assertNull(jsonObject.getAsString("parents"));
        assertNull(jsonObject.getAsNumber("parents"));
        assertNull(jsonObject.getAsObject("parents"));

        List<JsonObjectWrapper> parents = jsonObject.getAsObjectList("parents");
        boolean aliceFound = false;
        boolean bobFound = false;
        for (JsonObjectWrapper parent : parents) {
            String name = parent.getAsString("name");
            if ("Alice".equals(name)) {
                aliceFound = true;
            } else if ("Bob".equals(name)) {
                bobFound = true;
            }
        }
        assertTrue(aliceFound);
        assertTrue(bobFound);

        assertEquals(Collections.emptyList(), jsonObject.getAsObjectList("cats"));
        assertEquals(Arrays.asList("Lilly", "Mike"), jsonObject.getAsStringList("cats"));
        assertNull(jsonObject.getAsString("cats"));
        assertNull(jsonObject.getAsNumber("cats"));
        assertNull(jsonObject.getAsObject("cats"));

    }

    @Test
    void parseNullTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new JSONParser().parse((InputStream) null));
        assertEquals("InputStream cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> new JSONParser().parse((File) null));
        assertEquals("File cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> new JSONParser().parse((String) null));
        assertEquals("JSON String cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> new JSONParser().parse(new File("src/test/resources/sample.json"), null));
        assertEquals("URI cannot be null!", exception.getMessage());
    }

    @Test
    void notParsableTest() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> new JSONParser().parse("HelloWorld"));
        assertTrue(exception.getMessage().contains("Unable to parse JSON document!"));
    }

    @Test
    void emptyJSONTest() {
        JsonObjectWrapper jsonObject = new JSONParser().parse("{}");
        assertTrue(jsonObject.isEmpty());
    }

}
