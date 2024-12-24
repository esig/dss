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
package eu.europa.esig.dss.pki.jaxb.property;

/**
 * Utils class, containing a list of JAXB PKI properties
 *
 */
public final class PKIJaxbProperties {

    /** PKI Factory Host Url (for example: http://dss.nowina.lu/pki-factory/) */
    public static final String PKI_FACTORY_HOST = PropertiesLoader.getProperty("pki.factory.host");

    /** Two-letters country code (for example: LU) */
    public static final String PKI_FACTORY_COUNTRY = PropertiesLoader.getProperty("pki.factory.country", "CC");

    /** Organization name(for example: Nowina Solutions) */
    public static final String PKI_FACTORY_ORGANISATION = PropertiesLoader.getProperty("pki.factory.organisation", "Organization");

    /** Organization unit name (for example: PKI-Test) */
    public static final String PKI_FACTORY_ORGANISATION_UNIT = PropertiesLoader.getProperty("pki.factory.organisation.unit", "CERT FOR TEST");

    /** Extension of a CRL file (for example: ***.crl) */
    public static final String CRL_EXTENSION = PropertiesLoader.getProperty("pki.factory.crl.extension", ".crl");

    /** Preceding path to a CRL file (for example: crl/***) */
    public static final String CRL_PATH = PropertiesLoader.getProperty("pki.factory.crl.path", "crl/");

    /** Extension of a Certificate file (for example: ***.crt) */
    public static final String CERT_EXTENSION = PropertiesLoader.getProperty("pki.factory.cert.extension", ".crt");

    /** Preceding path to a Certificate file (for example: crt/***) */
    public static final String CERT_PATH = PropertiesLoader.getProperty("pki.factory.cert.path", "crt/");

    /** Extension of an OCSP file (for example: ***.ocsp) */
    public static final String OCSP_EXTENSION = PropertiesLoader.getProperty("pki.factory.ocsp.extension", "");

    /** Preceding path to an OCSP file (for example: ocsp/***) */
    public static final String OCSP_PATH = PropertiesLoader.getProperty("pki.factory.ocsp.path", "ocsp/");

    /**
     * Default constructor
     */
    private PKIJaxbProperties() {
        // empty
    }

}
