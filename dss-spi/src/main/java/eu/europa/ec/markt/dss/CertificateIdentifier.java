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

package eu.europa.ec.markt.dss;

import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * This class is used to obtain a unique DSS certificate's id. It is very helpful to follow the relationships between
 * certificates, CRLs, OCSPs and signatures. This DSS unique id is a simple integer number.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public final class CertificateIdentifier {

    /**
     * This is the id which is given to a new certificate.
     */
    private static int nextCertificateIdentifier = 1;


    /**
     * This boolean is used in testing context, to keep consistent ids for certificates between various test launches
     */
    private static boolean UNIQUE_IDENTIFIER = false;

    /**
     * This {@link LinkedHashMap} represents the association between the certificate unique identifier (certificate's
     * issuer distinguished name + "|" + certificate's serial number) and the DSS certificate's id.
     */
    private static LinkedHashMap<String, Integer> ids = new LinkedHashMap<String, Integer>();

    private CertificateIdentifier() {
    }

    public static boolean isUniqueIdentifier() {
        return UNIQUE_IDENTIFIER;
    }

    /**
     * This method is used to keep consistent ids for certificates between various test launches
     * @param uniqueIdentifier
     */
    public static void setUniqueIdentifier(boolean uniqueIdentifier) {
        UNIQUE_IDENTIFIER = uniqueIdentifier;
    }
    /**
     * Return the DSS certificate's unique id for a given {@link X509Certificate}. If the {@code cert} parameter is
     * null 0 is returned.
     *
     * @param cert
     * @return
     */
    public static int getId(final X509Certificate cert) {
        if (cert == null) {
            throw new DSSException("The certificate cannot be null!");
        }
        final String certKey = getKey(cert);
        Integer id = ids.get(certKey);
        if (id == null) {

            id = add(certKey);
        }
        return id;
    }

    /**
     * This method returns the DSS certificate's id based on the certificate's key: ( issuer distinguished name + "|" +
     * serial number). If the certificate is not yet stored it is added to the {@code ids}.
     *
     * @param key the key is composed of issuer distinguished name + "|" + serial number
     * @return DSS certificate's id
     */
    private static int add(final String key) {

        Integer id = ids.get(key);
        if (id == null) {
            if (UNIQUE_IDENTIFIER) {
                id = key.hashCode();
                ids.put(key, id);
            } else {
                id = nextCertificateIdentifier;
                ids.put(key, id);
                nextCertificateIdentifier++;
            }
        }
        return id;
    }

    /**
     * This method returns the unique identifier of a given {@link X509Certificate}. This identifier is used to obtain
     * the DSS certificate's unique id. The CANONICAL form of the {@code X500Principal} is used.
     *
     * @param cert
     * @return
     */
    private static String getKey(final X509Certificate cert) {

        final String canonicalIssuerX500Principal = cert.getIssuerX500Principal().getName(X500Principal.CANONICAL);
        final String serialNumber = cert.getSerialNumber().toString();
        return canonicalIssuerX500Principal + "|" + serialNumber;
    }

    /**
     * This method resets the list of certificates.
     */
    public static void clear() {
        ids.clear();
        nextCertificateIdentifier = 1;
    }

    /**
     * Returns the text representation of all certificates and their internal DSS number. The text is indented with the
     * given {@code indentStr} string.
     *
     * @param indentStr
     * @return
     */
    public static String toString(String indentStr) {

        StringBuilder sb = new StringBuilder();

        sb.append(indentStr).append("List of certificates:\n");
        for (Entry<String, Integer> entry : ids.entrySet()) {

            Integer id = entry.getValue();
            String key = entry.getKey();
            sb.append(indentStr).append(String.format("[%s] : %s\n", id, key));
        }
        return sb.toString();
    }
}
