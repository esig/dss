package eu.europa.esig.json;

import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RFC3339DateUtilsTest {

    @Test
    void getDateTest() {
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.set(2024, Calendar.OCTOBER, 13);

        assertNull(RFC3339DateUtils.getDate(null));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00Z"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T01:00:00Z"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00.00Z"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00.99Z"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00-00:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00-01:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00+00:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00+01:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00.000+00:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00.999+00:00"));
        assertThrows(IllegalArgumentException.class, () -> RFC3339DateUtils.getDate("2024"));
        assertThrows(IllegalArgumentException.class, () -> RFC3339DateUtils.getDate("0123456789"));
        assertThrows(IllegalArgumentException.class, () -> RFC3339DateUtils.getDate("HelloWorld"));
    }

    @Test
    void getDateTimeTest() {
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.set(2024, Calendar.OCTOBER, 13);

        assertNull(RFC3339DateUtils.getDateTime(null));
        assertThrows(IllegalArgumentException.class, () -> RFC3339DateUtils.getDateTime("2024-10-13"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00Z"));
        assertNotEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T01:00:00Z"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00.00Z"));
        assertNotEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00.99Z"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00-00:00"));
        assertNotEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00-01:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00+00:00"));
        assertNotEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00+01:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00.000+00:00"));
        assertNotEquals(calendar.getTime(), RFC3339DateUtils.getDateTime("2024-10-13T00:00:00.999+00:00"));
        assertThrows(IllegalArgumentException.class, () -> RFC3339DateUtils.getDateTime("2024"));
        assertThrows(IllegalArgumentException.class, () -> RFC3339DateUtils.getDateTime("0123456789"));
        assertThrows(IllegalArgumentException.class, () -> RFC3339DateUtils.getDateTime("HelloWorld"));
    }

}
