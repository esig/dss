/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

public final class RuleUtils {

    private RuleUtils() {
    }

    /**
     * The default date-time format: "yyyy-MM-dd'T'HH:mm:ss'Z'"
     */
    public static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

    /**
     * The default date pattern: "yyyy-MM-dd"
     */
    public static final SimpleDateFormat SDF_DATE = new SimpleDateFormat("yyyy-MM-dd");

    /**
     * Converts the given time duration (value) in the given unit (fromUnit) to given unit (toUnit).
     *
     * @param fromUnit
     * @param toUnit
     * @param value
     * @return
     */
    public static long convertDuration(final String fromUnit, final String toUnit, long value) {

        TimeUnit fromTimeUnit = null;
        if (fromUnit.equals("DAYS")) {

            fromTimeUnit = TimeUnit.DAYS;
        } else if (fromUnit.equals("HOURS")) {

            fromTimeUnit = TimeUnit.HOURS;
        } else if (fromUnit.equals("MINUTES")) {

            fromTimeUnit = TimeUnit.MINUTES;
        } else if (fromUnit.equals("SECONDS")) {

            fromTimeUnit = TimeUnit.SECONDS;
        } else if (fromUnit.equals("MILLISECONDS")) {

            fromTimeUnit = TimeUnit.MILLISECONDS;
        }
        try {

            if (toUnit.equals("MILLISECONDS")) {

                return TimeUnit.MILLISECONDS.convert(value, fromTimeUnit);
            } else if (toUnit.equals("DAYS")) {

                return TimeUnit.DAYS.convert(value, fromTimeUnit);
            } else if (toUnit.equals("HOURS")) {

                return TimeUnit.HOURS.convert(value, fromTimeUnit);
            } else if (toUnit.equals("MINUTES")) {

                return TimeUnit.MINUTES.convert(value, fromTimeUnit);
            } else if (toUnit.equals("SECONDS")) {

                return TimeUnit.SECONDS.convert(value, fromTimeUnit);
            }
            throw new DSSException("Unknown time unit: " + toUnit + ".");
        } catch (Exception e) {

            throw new DSSException("Error during the duration conversion: " + e.getMessage(), e);
        }
    }

    /**
     * Formats the given date-time using the SimpleDateFormat object.
     *
     * @param sdf
     * @param date
     * @return
     */
    public static String formatDate(final SimpleDateFormat sdf, final Date date) {

        final String stringDate = sdf.format(date);
        return stringDate;
    }

    /**
     * Formats the given date-time using the default pattern: {@link #SDF}
     *
     * @param date
     * @return
     */
    public static String formatDate(final Date date) {

        final String stringDate = SDF.format(date);
        return stringDate;
    }

    /**
     * Parses the given string date-time. The date-time must be defined using the default pattern: {@link #SDF}
     *
     * @param dateString formated date
     * @return computed {@code Date}
     * @throws DSSException if the conversion is not possible the {@code DSSException} is thrown.
     */
    public static Date parseDate(final String dateString) throws DSSException {

        try {

            final Date date = SDF.parse(dateString);
            return date;
        } catch (ParseException e) {
            throw new DSSException(e);
        }
    }

    /**
     * Parses the given string date-time. The date-time must be defined using the default pattern: {@link #SDF}
     *
     * @param dateString formated date
     * @return computed {@code Date} or null if the operation is not possible
     */
    public static Date parseSecureDate(final String dateString) {

        try {

            final Date date = SDF.parse(dateString);
            return date;
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Converts the given string representation of the date using the SimpleDateFormat object.
     *
     * @param format
     * @param dateString
     * @return
     */
    public static Date parseDate(final SimpleDateFormat format, final String dateString) {

        try {

            final Date date = format.parse(dateString);
            return date;
        } catch (ParseException e) {
            throw new DSSException(e);
        }
    }

    /**
     * Converts the given string representation of the date using the format pattern.
     *
     * @param format     the format to use
     * @param dateString the date string representation
     * @return the {@code Date}
     * @throws DSSException if the conversion is not possible the {@code DSSException} is thrown.
     */
    public static Date parseDate(final String format, final String dateString) throws DSSException {

        try {

            final SimpleDateFormat sdf = new SimpleDateFormat(format);
            final Date date = sdf.parse(dateString);
            return date;
        } catch (ParseException e) {
            throw new DSSException(e);
        }
    }

    /**
     * @param id
     * @param idList
     * @return
     */
    public static boolean contains(final String id, final List<XmlDom> idList) {

        boolean found = false;
        for (XmlDom xmlDom : idList) {

            String value = xmlDom.getValue("./text()");
            if (value.equals(id)) {

                found = true;
                break;
            }
        }
        return found;
    }

    /**
     * This method checks if the given string is present in the list of {@code String}(s).
     *
     * @param id     {@code String} to check
     * @param idList the list of {@code String}(s)
     * @return tru if the {@code id} is present in the {@code idList}, false otherwise
     */
    public static boolean contains1(final String id, final List<String> idList) {

        boolean found = false;
        if (id != null && idList != null) {

            for (final String idFromList : idList) {

                if (idFromList.equals(id)) {

                    found = true;
                    break;
                }
            }
        }
        return found;
    }

    public static long convertToLong(final String value) {

        try {

            return Long.parseLong(value);
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }

    public static String canonicalizeDigestAlgo(final String algo) {

        String digestAlgo = algo.trim().replace("-", "").toUpperCase();
        return digestAlgo;
    }

    public static String canonicalizeEncryptionAlgo(final String algo) {

        String digestAlgo = algo.trim().replace("-", "").toUpperCase();
        return digestAlgo;
    }

    public static String canonicalizeSignatureAlgo(final String algo) {

        String signatureAlgo = algo.trim().replace("-", "").replace("Encryption", "").toUpperCase().replace("WITH", "with");
        return signatureAlgo;
    }

    public static boolean in(final String value, final String... values) {

        final boolean contains = Arrays.asList(values).contains(value);
        return contains;

    }

    public static String toString(List<String> strings) {

        final String SEPARATOR = ",";
        final StringBuilder stringBuilder = new StringBuilder();
        for (final String string : strings) {

            if (stringBuilder.length() != 0) {

                stringBuilder.append(SEPARATOR).append(' ');
            }
            stringBuilder.append(string);
        }
        return stringBuilder.toString();
    }

    public static boolean contains(final List<String> requested, final List<String> claimed) {

        boolean found = false;
        for (final String element : requested) {

            if (!claimed.contains(element)) {
                found = false;
                break;
            }
            found = true;
        }
        return found;
    }
}
