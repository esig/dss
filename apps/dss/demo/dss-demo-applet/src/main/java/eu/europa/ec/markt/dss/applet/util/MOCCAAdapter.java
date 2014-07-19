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

package eu.europa.ec.markt.dss.applet.util;

import java.lang.reflect.Constructor;

import eu.europa.ec.markt.dss.signature.token.PasswordInputCallback;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;

/**
 * Creates MOCCA Signature Token Connection
 *
 * @version $Revision: 1182 $ - $Date: 2012-03-08 11:48:33 +0100 (Thu, 08 Mar 2012) $
 */

public class MOCCAAdapter {

    private static final String CONNECTION_CLASS = "eu.europa.ec.markt.dss.mocca.MOCCASignatureTokenConnection";

    private Class<?> getSignatureTokenConnectionClass() {
        try {
            return Class.forName(CONNECTION_CLASS);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    public boolean isMOCCAAvailable() {
        return getSignatureTokenConnectionClass() != null;
    }

    public SignatureTokenConnection createSignatureToken(PasswordInputCallback callback) {
        Class<?> clasz = getSignatureTokenConnectionClass();
        if (clasz == null) {
            throw new NullPointerException();
        } else {
            try {
                Constructor<?> c = clasz.getConstructor(PasswordInputCallback.class);
                return (SignatureTokenConnection) c.newInstance(callback);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

}
