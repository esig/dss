package eu.europa.esig.json;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Utility class for converting RFC 3339 datetime.
 *
 */
public final class RFC3339DateUtils {

    /** Format date-time as specified in RFC 3339 5.6 */
    private static final String[] DATE_PATTERNS;

    static {
        // RFC 3339 cannot be fully represented in Java
        // see {@link <a href="https://stackoverflow.com/questions/40369287/what-pattern-should-be-used-to-parse-rfc-3339-datetime-strings-in-java">link</a>
        DATE_PATTERNS = new String[]{
                "yyyy-MM-dd",
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
                "yyyy-MM-dd'T'HH:mm:ssXXX",
                "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"
        };
    }

    /**
     * Parses a IETF RFC 3339 dateTime String
     *
     * @param dateTimeString {@link String} in the RFC 3339 format to parse
     * @return {@link Date}
     */
    public static Date getDate(String dateTimeString) {
        for (String pattern : DATE_PATTERNS) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat(pattern);
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                return sdf.parse(dateTimeString);
            } catch (ParseException e) {
                // try next pattern
            }
        }

        throw new IllegalArgumentException("Unparseable date: " + dateTimeString);
    }

}
