package eu.europa.esig.json;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Utility class for parsing RFC 3339 dates and times formats.
 *
 */
public final class RFC3339DateUtils {

    /** Format date as specified in RFC 3339 5.6 */
    private static final String DATE_PATTERN;

    /** Format date-time as specified in RFC 3339 5.6 */
    private static final String[] DATE_TIME_PATTERNS;

    static {
        DATE_PATTERN = "yyyy-MM-dd";
        // RFC 3339 cannot be fully represented in Java
        // see {@link <a href="https://stackoverflow.com/questions/40369287/what-pattern-should-be-used-to-parse-rfc-3339-datetime-strings-in-java">link</a>
        DATE_TIME_PATTERNS = new String[]{
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
                "yyyy-MM-dd'T'HH:mm:ssXXX",
                "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"
        };
    }

    /**
     * Parses a IETF RFC 3339 date String
     *
     * @param dateString {@link String} in the RFC 3339 format to parse
     * @return {@link Date}
     */
    public static Date getDate(String dateString) {
        if (dateString == null) {
            return null;
        }

        try {
            SimpleDateFormat sdf = new SimpleDateFormat(DATE_PATTERN);
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            return sdf.parse(dateString);
        } catch (ParseException e) {
            throw new IllegalArgumentException(String.format("Invalid 'date format': %s", dateString));
        }

    }

    /**
     * Parses a IETF RFC 3339 date-time String
     *
     * @param dateTimeString {@link String} in the RFC 3339 format to parse
     * @return {@link Date}
     */
    public static Date getDateTime(String dateTimeString) {
        if (dateTimeString == null) {
            return null;
        }

        for (String pattern : DATE_TIME_PATTERNS) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat(pattern);
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                return sdf.parse(dateTimeString);
            } catch (ParseException e) {
                // try next pattern
            }
        }

        throw new IllegalArgumentException(String.format("Unparseable 'date-time': %s", dateTimeString));
    }

}
