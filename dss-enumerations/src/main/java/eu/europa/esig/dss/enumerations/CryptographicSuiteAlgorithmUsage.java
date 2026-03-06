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
package eu.europa.esig.dss.enumerations;

/**
 * Lists possible algorithm-usage element URIs as per ETSI TS 119 322.
 *
 */
public enum CryptographicSuiteAlgorithmUsage implements UriBasedEnum {

    /**
     * http://uri.etsi.org/19322/sign_data shall be used to indicate that the evaluation is applicable for any signed
     * data.
     */
    SIGN_DATA("http://uri.etsi.org/19322/sign_data"),

    /**
     * http://uri.etsi.org/19322/sign_data/sign_certificates shall be used to indicate that the evaluation is applicable
     * for signing certificates.
     */
    SIGN_CERTIFICATES("http://uri.etsi.org/19322/sign_data/sign_certificates"),

    /**
     * http://uri.etsi.org/19322/sign_data/sign_ocsp shall be used to indicate that the evaluation is applicable for
     * signing OCSP responses.
     */
    SIGN_OCSP("http://uri.etsi.org/19322/sign_data/sign_ocsp"),

    /**
     * http://uri.etsi.org/19322/sign_data/sign_timestamps shall be used to indicate that the evaluation is applicable
     * for signing timestamps.
     */
    SIGN_TIMESTAMPS("http://uri.etsi.org/19322/sign_data/sign_timestamps"),

    /**
     * http://uri.etsi.org/19322/sign_data/validate_data shall be used to indicate that the evaluation is applicable for
     * the validation of any signed data.
     */
    VALIDATE_DATA("http://uri.etsi.org/19322/sign_data/validate_data"),

    /**
     * http://uri.etsi.org/19322/sign_data/validate_data/validate_certificates shall be used to indicate that the
     * evaluation is applicable for the validation of certificates.
     */
    VALIDATE_CERTIFICATES("http://uri.etsi.org/19322/sign_data/validate_data/validate_certificates"),

    /**
     * http://uri.etsi.org/19322/sign_data/validate_data/validate_ocsp shall be used to indicate that the evaluation is
     * applicable for the validation of OCSP responses.
     */
    VALIDATE_OCSP("http://uri.etsi.org/19322/sign_data/validate_data/validate_ocsp"),

    /**
     * http://uri.etsi.org/19322/sign_data/validate_data/validate_timestamps shall be used to indicate that the
     * evaluation is applicable for the validation of timestamps.
     */
    VALIDATE_TIMESTAMPS("http://uri.etsi.org/19322/sign_data/validate_data/validate_timestamps");

    /** URI identifier of the algorithm-usage element */
    private final String uri;

    /**
     * Default constructor
     *
     * @param uri {@link String}
     */
    CryptographicSuiteAlgorithmUsage(final String uri) {
        this.uri = uri;
    }

    @Override
    public String getUri() {
        return uri;
    }

    /**
     * Returns a {@code CryptographicSuiteAlgorithmUsage} by the given URI
     *
     * @param uri {@link String} to get {@link CryptographicSuiteAlgorithmUsage} for
     * @return {@link CryptographicSuiteAlgorithmUsage}
     */
    public static CryptographicSuiteAlgorithmUsage fromUri(String uri) {
        if (uri != null) {
            for (CryptographicSuiteAlgorithmUsage algorithmUsage : CryptographicSuiteAlgorithmUsage.values()) {
                if (algorithmUsage.uri.equals(uri)) {
                    return algorithmUsage;
                }
            }
        }
        return null;
    }

}
