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
package eu.europa.esig.dss.validation.reports.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlConnectionInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTLSCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTLSCertificateBindingSignature;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;

/**
 * Builds a Diagnostic Data report for a QWAC certificate validation
 *
 */
public class QWACCertificateDiagnosticDataBuilder extends SignedDocumentDiagnosticDataBuilder {

    /** URL used to establish a remote connection to verify a TLS/SSL certificate for */
    private String websiteUrl;

    /** TLS/SSL certificate returned by a remote server during the TLS/SSL handshake */
    private CertificateToken tlsCertificate;

    /** TLS Certificate Binding URL, when present (under the 'Link' response header) */
    private String tlsCertificateBindingUrl;

    /** TLS Certificate Binding Signature, when present */
    private AdvancedSignature tlsCertificateBindingSignature;

    /** Builder used to build a signature object */
    private SignedDocumentDiagnosticDataBuilder signatureDiagnosticDataBuilder;

    /**
     * Default constructor
     */
    public QWACCertificateDiagnosticDataBuilder() {
        // empty
    }

    /**
     * Sets the website URL used to establish a TLS connection
     *
     * @param websiteUrl {@link String}
     * @return {@link QWACCertificateDiagnosticDataBuilder}
     */
    public QWACCertificateDiagnosticDataBuilder websiteUrl(String websiteUrl) {
        this.websiteUrl = websiteUrl;
        return this;
    }

    /**
     * Sets the TLS/SSL certificate obtained during the handshake
     *
     * @param tlsCertificate {@link CertificateToken}
     * @return {@link QWACCertificateDiagnosticDataBuilder}
     */
    public QWACCertificateDiagnosticDataBuilder tlsCertificate(CertificateToken tlsCertificate) {
        this.tlsCertificate = tlsCertificate;
        return this;
    }

    /**
     * Sets the TLS Certificate Binding URL, when present (unde the 'Link' response header)
     *
     * @param tlsCertificateBindingUrl {@link String}
     * @return {@link QWACCertificateDiagnosticDataBuilder}
     */
    public QWACCertificateDiagnosticDataBuilder tlsCertificateBindingUrl(String tlsCertificateBindingUrl) {
        this.tlsCertificateBindingUrl = tlsCertificateBindingUrl;
        return this;
    }

    /**
     * Sets the TLS Certificate Binding signature, when present
     *
     * @param tlsCertificateBindingSignature {@link AdvancedSignature}
     * @return {@link QWACCertificateDiagnosticDataBuilder}
     */
    public QWACCertificateDiagnosticDataBuilder tlsCertificateBindingSignature(AdvancedSignature tlsCertificateBindingSignature) {
        this.tlsCertificateBindingSignature = tlsCertificateBindingSignature;
        return this;
    }

    /**
     * Sets a builder for a signature object
     *
     * @param signatureDiagnosticDataBuilder {@link SignedDocumentDiagnosticDataBuilder}
     * @return {@link QWACCertificateDiagnosticDataBuilder}
     */
    public QWACCertificateDiagnosticDataBuilder setSignatureDiagnosticDataBuilder(SignedDocumentDiagnosticDataBuilder signatureDiagnosticDataBuilder) {
        this.signatureDiagnosticDataBuilder = signatureDiagnosticDataBuilder;
        return this;
    }

    @Override
    public XmlDiagnosticData build() {
        XmlDiagnosticData xmlDiagnosticData = super.build();
        xmlDiagnosticData.setConnectionInfo(buildXmlConnectionInfo());
        return xmlDiagnosticData;
    }

    private XmlConnectionInfo buildXmlConnectionInfo() {
        XmlConnectionInfo xmlConnectionInfo = new XmlConnectionInfo();
        if (websiteUrl != null) {
            xmlConnectionInfo.setUrl(websiteUrl);
        }
        if (tlsCertificate != null) {
            XmlTLSCertificate xmlTLSCertificate = new XmlTLSCertificate();
            xmlTLSCertificate.setCertificate(xmlCertsMap.get(tlsCertificate.getDSSIdAsString()));
            xmlConnectionInfo.setTLSCertificate(xmlTLSCertificate);
        }
        if (tlsCertificateBindingUrl != null) {
            xmlConnectionInfo.setTLSCertificateBindingUrl(tlsCertificateBindingUrl);
        }
        if (tlsCertificateBindingSignature != null) {
            XmlTLSCertificateBindingSignature xmlTLSCertificateBindingSignature = new XmlTLSCertificateBindingSignature();
            xmlTLSCertificateBindingSignature.setSignature(xmlSignaturesMap.get(tlsCertificateBindingSignature.getId()));
            xmlConnectionInfo.setTLSCertificateBindingSignature(xmlTLSCertificateBindingSignature);
        }
        return xmlConnectionInfo;
    }

    @Override
    public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
        XmlSignature xmlSignature = signatureDiagnosticDataBuilder.buildDetachedXmlSignature(signature);
        identifyTLSCertificates(xmlSignature);
        return xmlSignature;
    }

    private void identifyTLSCertificates(XmlSignature xmlSignature) {
        for (XmlDigestMatcher digestMatcher : xmlSignature.getDigestMatchers()) {
            if (DigestMatcherType.SIG_D_ENTRY == digestMatcher.getType()
                    && digestMatcher.isDataFound() && digestMatcher.isDataIntact()) {
                CertificateToken matchingTLSCertificate = getMatchingTLSCertificate(digestMatcher);
                if (matchingTLSCertificate != null) {
                    digestMatcher.setDataObjectReferences(Collections.singletonList(identifierProvider.getIdAsString(matchingTLSCertificate)));
                }
            }
        }
    }

    private CertificateToken getMatchingTLSCertificate(XmlDigestMatcher digestMatcher) {
        for (CertificateToken certificate : usedCertificates) {
            if (Arrays.equals(digestMatcher.getDigestValue(), certificate.getDigest(digestMatcher.getDigestMethod()))) {
                return certificate;
            }
        }
        return null;
    }

    @Override
    protected void assertConfigurationValid() {
        Objects.requireNonNull(websiteUrl, "websiteUrl shall be provided!");
    }

}
