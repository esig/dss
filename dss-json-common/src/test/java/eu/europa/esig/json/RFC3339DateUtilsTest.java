package eu.europa.esig.json;

import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RFC3339DateUtilsTest {

    @Test
    void getDateTest() {
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.set(2024, Calendar.OCTOBER, 13);

        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00Z"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00.00Z"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00-00:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00+00:00"));
        assertEquals(calendar.getTime(), RFC3339DateUtils.getDate("2024-10-13T00:00:00.000+00:00"));
    }

}
