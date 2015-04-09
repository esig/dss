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
package eu.europa.esig.dss.tsl;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSEncodingException;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This CertificateSource keep a list of trusted certificates extracted from the trusted list. To populate this list {@link
 * TrustedListsCertificateSource} class is used. This list is refreshed when the method refresh
 * is called.
 *
 *
 */

public class ReloadableTrustedListCertificateSource extends TrustedListsCertificateSource {

    private static final Logger LOG = LoggerFactory.getLogger(ReloadableTrustedListCertificateSource.class);

    private TrustedListsCertificateSource currentSource = new TrustedListsCertificateSource();

    public ReloadableTrustedListCertificateSource() {

        super();
    }

    static class Reloader implements Runnable {

        private TrustedListsCertificateSource underlyingSource;

        Reloader(final TrustedListsCertificateSource underlyingSource) {

            this.underlyingSource = underlyingSource;
        }

        @Override
        public void run() {

            try {

                LOG.info("--> run(): START LOADING");
                underlyingSource.init();
                LOG.info("--> run(): END LOADING");

            } catch (DSSEncodingException e) {
                makeATrace(e);
            }
        }

        private static void makeATrace(final Exception e) {

            LOG.error(e.getMessage(), e);
        }
    }

    public synchronized void refresh() {

        final TrustedListsCertificateSource newSource = new TrustedListsCertificateSource(this);
	    final Reloader target = new Reloader(newSource);
	    final Thread reloader = new Thread(target);
        LOG.debug("--> refresh(): START");
        reloader.start();
        LOG.debug("--> refresh(): END");

        currentSource = newSource;
    }

    public Map<String, String> getDiagnosticInfo() {

        return currentSource.getDiagnosticInfo();
    }

    @Override
    public CertificatePool getCertificatePool() {

        return currentSource.getCertificatePool();
    }

    @Override
    /**
     * Retrieves the list of all certificate tokens from this source.
     *
     * @return
     */
    public List<CertificateToken> getCertificates() {

        return currentSource.getCertificatePool().getCertificateTokens();
    }
}
