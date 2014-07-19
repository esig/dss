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
package eu.europa.ec.markt.dss.validation102853.https;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.apache.http.conn.ssl.X509HostnameVerifier;

/**
 * 
 * A X509HostnameVerifier for allow all hostnames.
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class OptimistX509HostnameVerifier implements X509HostnameVerifier {
    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.HostnameVerifier#verify(java.lang.String, javax.net.ssl.SSLSession)
     */
    @Override
    public boolean verify(String arg0, SSLSession arg1) {
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.http.conn.ssl.X509HostnameVerifier#verify(java.lang.String, javax.net.ssl.SSLSocket)
     */
    @Override
    public void verify(String host, SSLSocket ssl) throws IOException {
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.http.conn.ssl.X509HostnameVerifier#verify(java.lang.String, java.lang.String[],
     * java.lang.String[])
     */
    @Override
    public void verify(String host, String[] cns, String[] subjectAlts) throws SSLException {
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.http.conn.ssl.X509HostnameVerifier#verify(java.lang.String, java.security.cert.X509Certificate)
     */
    @Override
    public void verify(String host, X509Certificate cert) throws SSLException {
    }

}
