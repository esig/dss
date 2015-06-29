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
package eu.europa.esig.dss.applet.util;

import java.lang.reflect.Constructor;

import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.SignatureTokenConnection;

/**
 * Creates MOCCA Signature Token Connection
 *
 *
 */

public class MOCCAAdapter {

	private static final String CONNECTION_CLASS = "eu.europa.esig.dss.token.mocca.MOCCASignatureTokenConnection";

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
