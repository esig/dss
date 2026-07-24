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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlQualifier;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public abstract class TrustedSourceServiceWrapper {

    /** Trusted Entity names */
    private List<String> entityNames;

    /** Trusted Entity trade names */
    private List<String> tradeNames;

    /** Related certificate */
    private CertificateWrapper serviceDigitalIdentifier;

    /** Trusted service names */
    private List<String> serviceNames;

    /** Country code */
    private String countryCode;

    /** Status */
    private String status;

    /** Service Type Identifier URI */
    private String type;

    /** Start date of validity */
    private Date startDate;

    /** End date of validity */
    private Date endDate;

    /** Captured qualifiers */
    private List<XmlQualifier> capturedQualifiers;

    /** Additional service informations */
    private List<String> additionalServiceInfos;

    /**
     * Default constructor
     */
    protected TrustedSourceServiceWrapper() {
        // empty
    }

    /**
     * Gets Trusted Service Provider names
     *
     * @return list of {@link String}s
     */
    public List<String> getEntityNames() {
        return entityNames;
    }

    /**
     * Sets Trusted Service Provider names
     *
     * @param entityNames list of {@link String}s
     */
    public void setEntityNames(List<String> entityNames) {
        this.entityNames = entityNames;
    }

    /**
     * Gets Trusted Service Provider trade names
     *
     * @return list of {@link String}s
     */
    public List<String> getTradeNames() {
        return tradeNames;
    }

    /**
     * Sets Trusted Service Provider trade names
     *
     * @param tradeNames list of {@link String}s
     */
    public void setTradeNames(List<String> tradeNames) {
        this.tradeNames = tradeNames;
    }

    /**
     * Gets Service Digital Identifier Certificate
     *
     * @return {@link CertificateWrapper}
     */
    public CertificateWrapper getServiceDigitalIdentifier() {
        return serviceDigitalIdentifier;
    }

    /**
     * Sets Service Digital Identifier Certificate
     *
     * @param serviceDigitalIdentifier {@link CertificateWrapper}
     */
    public void setServiceDigitalIdentifier(CertificateWrapper serviceDigitalIdentifier) {
        this.serviceDigitalIdentifier = serviceDigitalIdentifier;
    }

    /**
     * Gets service names
     *
     * @return list of {@link String}s
     */
    public List<String> getServiceNames() {
        return serviceNames;
    }

    /**
     * Sets service names
     *
     * @param serviceNames list of {@link String}s
     */
    public void setServiceNames(List<String> serviceNames) {
        this.serviceNames = serviceNames;
    }

    /**
     * Gets country code
     *
     * @return {@link String}
     */
    public String getCountryCode() {
        return countryCode;
    }

    /**
     * Sets country code
     *
     * @param countryCode {@link String}
     */
    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    /**
     * Gets revocation
     *
     * @return {@link String}
     */
    public String getStatus() {
        return status;
    }

    /**
     * Sets revocation
     *
     * @param status {@link String}
     */
    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * Gets type
     *
     * @return {@link String}
     */
    public String getType() {
        return type;
    }

    /**
     * Sets type
     *
     * @param type {@link String}
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Gets TrustService start validity date
     *
     * @return {@link Date}
     */
    public Date getStartDate() {
        return startDate;
    }

    /**
     * Sets TrustService start validity date
     *
     * @param startDate {@link Date}
     */
    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    /**
     * Gets TrustService end validity date
     *
     * @return {@link Date}
     */
    public Date getEndDate() {
        return endDate;
    }

    /**
     * Sets TrustService end validity date
     *
     * @param endDate {@link Date}
     */
    public void setEndDate(Date endDate) {
        this.endDate = endDate;
    }

    /**
     * Gets captured qualifiers
     *
     * @return list of {@link String}s
     */
    public List<XmlQualifier> getCapturedQualifiers() {
        return capturedQualifiers;
    }

    /**
     * Gets captured qualifiers
     *
     * @return list of {@link String}s
     */
    public List<String> getCapturedQualifierUris() {
        if (capturedQualifiers != null) {
            return capturedQualifiers.stream().map(XmlQualifier::getValue).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    /**
     * Sets captured qualifiers
     *
     * @param capturedQualifiers list of {@link String}s
     */
    public void setCapturedQualifiers(List<XmlQualifier> capturedQualifiers) {
        this.capturedQualifiers = capturedQualifiers;
    }

    /**
     * Gets additional service informations
     *
     * @return list of {@link String}s
     */
    public List<String> getAdditionalServiceInfos() {
        return additionalServiceInfos;
    }

    /**
     * Sets additional service informations
     *
     * @param additionalServiceInfos list of {@link String}s
     */
    public void setAdditionalServiceInfos(List<String> additionalServiceInfos) {
        this.additionalServiceInfos = additionalServiceInfos;
    }

}
