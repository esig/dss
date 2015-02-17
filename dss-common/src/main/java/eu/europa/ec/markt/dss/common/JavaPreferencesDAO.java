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

package eu.europa.ec.markt.dss.common;

import java.util.prefs.Preferences;

/**
 * Stores the user preferences in the Java Preferences API.
 *
 * @version $Revision$ - $Date$
 */

public class JavaPreferencesDAO implements UserPreferencesDAO {

    private static final String PKCS11LIB = "PKCS11LIB";
    private static final String PKCS12FILE = "PKCS12FILE";
    private static final String TOKEN_TYPE = "TOKEN_TYPE";

    private Preferences getPreferences() {
        return Preferences.userNodeForPackage(this.getClass());
    }

    @Override
    public void setPKCS11LibraryPath(String pkcs11LibraryPath) {
        Preferences preferences = getPreferences();
        preferences.put(PKCS11LIB, pkcs11LibraryPath);
    }

    @Override
    public String getPKCS11LibraryPath() {
        Preferences preferences = getPreferences();
        return preferences.get(PKCS11LIB, null);
    }

    @Override
    public void setSignatureTokenType(SignatureTokenType tokenType) {
        Preferences preferences = getPreferences();
        preferences.put(TOKEN_TYPE, tokenType.toString());
    }

    @Override
    public SignatureTokenType getSignatureTokenType() {
        Preferences preferences = getPreferences();
        if (preferences.get(TOKEN_TYPE, null) != null) {
            return SignatureTokenType.valueOf(preferences.get(TOKEN_TYPE, null));
        } else {
            return null;
        }
    }

    @Override
    public void setPKCS12FilePath(String path) {
        Preferences preferences = getPreferences();
        preferences.put(PKCS12FILE, path);
    }

    @Override
    public String getPKCS12FilePath() {
        Preferences preferences = getPreferences();
        return preferences.get(PKCS12FILE, null);
    }
}