/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.x509;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import eu.europa.esig.dss.DSSEncodingException;
import eu.europa.esig.dss.DSSEncodingException.MSG;

/**
 * Implements a CertificateSource using a JKS KeyStore.
 *
 *
 */

public class KeyStoreCertificateSource extends CommonCertificateSource {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(KeyStoreCertificateSource.class);

    private File keyStoreFile;

    private String password;

    private String keyStoreType;

    /**
     * The default constructor for KeyStoreCertificateSource.
     *
     * @param keyStoreFilename
     * @param password
     * @param certPool
     */
    public KeyStoreCertificateSource(final String keyStoreFilename, final String password, final CertificatePool certPool) {

        this(new File(keyStoreFilename), "JKS", password, certPool);
    }

    /**
     * The default constructor for KeyStoreCertificateSource.
     *
     * @param keyStoreFile
     * @param password
     * @param certPool
     */
    public KeyStoreCertificateSource(final File keyStoreFile, final String password, final CertificatePool certPool) {

        this(keyStoreFile, "JKS", password, certPool);
    }

    /**
     * The default constructor for KeyStoreCertificateSource.
     *
     * @param keyStoreFile
     * @param keyStoreType
     * @param password
     * @param certPool
     */
    public KeyStoreCertificateSource(final File keyStoreFile, final String keyStoreType, final String password, final CertificatePool certPool) {

        super(certPool);
        this.keyStoreFile = keyStoreFile;
        this.keyStoreType = keyStoreType;
        this.password = password;

        this.certificateTokens = populate();
    }

    /**
     * The default constructor for KeyStoreCertificateSource without <code>CertificatePool</code>.
     *
     * @param keyStoreFilename
     * @param password
     */
    public KeyStoreCertificateSource(final String keyStoreFilename, final String password) {

        this(new File(keyStoreFilename), "JKS", password);
    }

    /**
     * The default constructor for KeyStoreCertificateSource without <code>CertificatePool</code>.
     *
     * @param keyStoreFile
     * @param password
     */
    public KeyStoreCertificateSource(final File keyStoreFile, final String password) {

        this(keyStoreFile, "JKS", password);
    }

    /**
     * The default constructor for KeyStoreCertificateSource without <code>CertificatePool</code>.
     *
     * @param keyStoreFile
     * @param keyStoreType
     * @param password
     */
    public KeyStoreCertificateSource(final File keyStoreFile, final String keyStoreType, final String password) {

        super();
        this.keyStoreFile = keyStoreFile;
        this.keyStoreType = keyStoreType;
        this.password = password;

        this.certificateTokens = populate();
    }

    private List<CertificateToken> populate() {

        ArrayList<CertificateToken> list = new ArrayList<CertificateToken>();
        try {

            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(new FileInputStream(keyStoreFile), password.toCharArray());
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {

                String alias = aliases.nextElement();
                final Certificate certificate = keyStore.getCertificate(alias);
                if (certificate != null) {
                    X509Certificate x509Certificate = (X509Certificate) certificate;
                    LOG.debug("Alias " + alias + " Cert " + x509Certificate.getSubjectDN());

                    CertificateToken certToken = certPool.getInstance(new CertificateToken(x509Certificate), CertificateSourceType.OTHER);
                    list.add(certToken);
                }
                if (keyStore.getCertificateChain(alias) != null) {

                    for (Certificate chainCert : keyStore.getCertificateChain(alias)) {

                        LOG.debug("Alias " + alias + " Cert " + ((X509Certificate) chainCert).getSubjectDN());
                        CertificateToken certToken = certPool.getInstance(new CertificateToken((X509Certificate) chainCert), CertificateSourceType.OCSP_RESPONSE);
                        if (!list.contains(certToken)) {

                            list.add(certToken);
                        }
                    }
                }
            }
        } catch (CertificateException e) {
            throw new DSSEncodingException(MSG.CERTIFICATE_CANNOT_BE_READ, e);
        } catch (KeyStoreException e) {
            throw new DSSEncodingException(MSG.CERTIFICATE_CANNOT_BE_READ, e);
        } catch (NoSuchAlgorithmException e) {
            throw new DSSEncodingException(MSG.CERTIFICATE_CANNOT_BE_READ, e);
        } catch (FileNotFoundException e) {
            throw new DSSEncodingException(MSG.CERTIFICATE_CANNOT_BE_READ, e);
        } catch (IOException e) {
            throw new DSSEncodingException(MSG.CERTIFICATE_CANNOT_BE_READ, e);
        }
        return list;
    }
}
