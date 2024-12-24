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

import java.util.List;

/**
 * This enumeration represents an AdditionalServiceInformation element content present in a Trusted List
 *
 */
public enum AdditionalServiceInformation {

    /**
     * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures": in order to further specify the
     * "Service type identifier" identified service as being provided for electronic signatures;
     */
    FOR_ESIGNATURES("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"),

    /**
     * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals": in order to further specify the
     * "Service type identifier" identified service as being provided for electronic seals;
     */
    FOR_ESEALS("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals"),

    /**
     * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication": in order to further specify the
     * "Service type identifier" identified service as being provided for web site authentication;
     */
    FOR_WEB_AUTHENTICATION("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication");

    /** Defines URI of the enumeration */
    private final String uri;

    /**
     * Default constructor
     *
     * @param uri {@link String}
     */
    AdditionalServiceInformation(String uri) {
        this.uri= uri;
    }

    /**
     * Gets URI of the AdditionalServiceInformation
     *
     * @return {@link String}
     */
    public String getUri() {
        return uri;
    }

    /**
     * This method returns {@code AdditionalServiceInformation} for the given {@code uri}
     *
     * @param uri {@link String} to get {@link AdditionalServiceInformation} for
     * @return {@link AdditionalServiceInformation} if exists, null otherwise
     */
    public static AdditionalServiceInformation getByUri(String uri) {
        if (uri != null) {
            for (AdditionalServiceInformation serviceQualification : AdditionalServiceInformation.values()) {
                if (uri.equals(serviceQualification.getUri())) {
                    return serviceQualification;
                }
            }
        }
        return null;
    }

    /**
     * Checks if the given additional service info is "for eSignatures" identifier
     *
     * @param additionalServiceInfo {@link String}s to verify
     * @return TRUE if the "for eSignatures" identifier, FALSE otherwise
     */
    public static boolean isForeSignatures(String additionalServiceInfo) {
        return FOR_ESIGNATURES.getUri().equals(additionalServiceInfo);
    }

    /**
     * Checks if the given additional service info is "for eSeals" identifier
     *
     * @param additionalServiceInfo {@link String}s to verify
     * @return TRUE if the "for eSeals" identifier, FALSE otherwise
     */
    public static boolean isForeSeals(String additionalServiceInfo) {
        return FOR_ESEALS.getUri().equals(additionalServiceInfo);
    }

    /**
     * Checks if the given additional service info is "for web authentication" identifier
     *
     * @param additionalServiceInfo {@link String}s to verify
     * @return TRUE if the "for web authentication" identifier, FALSE otherwise
     */
    public static boolean isForWebAuth(String additionalServiceInfo) {
        return FOR_WEB_AUTHENTICATION.getUri().equals(additionalServiceInfo);
    }

    /**
     * Checks if the given list of additional service infos contains "for eSignatures" identifier
     *
     * @param additionalServiceInfos a list of {@link String}s to verify
     * @return TRUE if the list contains "for eSignatures" identifier, FALSE otherwise
     */
    public static boolean isForeSignatures(List<String> additionalServiceInfos) {
        return additionalServiceInfos.contains(FOR_ESIGNATURES.getUri());
    }

    /**
     * Checks if the given list of additional service infos contains "for eSeals" identifier
     *
     * @param additionalServiceInfos a list of {@link String}s to verify
     * @return TRUE if the list contains "for eSeals" identifier, FALSE otherwise
     */
    public static boolean isForeSeals(List<String> additionalServiceInfos) {
        return additionalServiceInfos.contains(FOR_ESEALS.getUri());
    }

    /**
     * Checks if the given list of additional service infos contains "for web authentication" identifier
     *
     * @param additionalServiceInfos a list of {@link String}s to verify
     * @return TRUE if the list contains "for web authentication" identifier, FALSE otherwise
     */
    public static boolean isForWebAuth(List<String> additionalServiceInfos) {
        return additionalServiceInfos.contains(FOR_WEB_AUTHENTICATION.getUri());
    }

    /**
     * Checks if the given list of additional service infos only contains "for eSignatures" identifier
     *
     * @param additionalServiceInfos a list of {@link String}s to verify
     * @return TRUE if the list only contains "for eSignatures" identifier, FALSE otherwise
     */
    public static boolean isForeSignaturesOnly(List<String> additionalServiceInfos) {
        return additionalServiceInfos != null && additionalServiceInfos.size() == 1 && isForeSignatures(additionalServiceInfos);
    }

    /**
     * Checks if the given list of additional service infos only contains "for eSeals" identifier
     *
     * @param additionalServiceInfos a list of {@link String}s to verify
     * @return TRUE if the list only contains "for eSeals" identifier, FALSE otherwise
     */
    public static boolean isForeSealsOnly(List<String> additionalServiceInfos) {
        return additionalServiceInfos != null && additionalServiceInfos.size() == 1 && isForeSeals(additionalServiceInfos);
    }

    /**
     * Checks if the given list of additional service infos only contains "for web authentication" identifier
     *
     * @param additionalServiceInfos a list of {@link String}s to verify
     * @return TRUE if the list only contains "for web authentication" identifier, FALSE otherwise
     */
    public static boolean isForWebAuthOnly(List<String> additionalServiceInfos) {
        return additionalServiceInfos != null && additionalServiceInfos.size() == 1 && isForWebAuth(additionalServiceInfos);
    }

}
