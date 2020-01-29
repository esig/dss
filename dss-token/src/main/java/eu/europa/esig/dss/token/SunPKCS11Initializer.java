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
package eu.europa.esig.dss.token;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.Provider;

import eu.europa.esig.dss.model.DSSException;

public final class SunPKCS11Initializer {

	private static final String SUN_PKCS11_CLASSNAME = "sun.security.pkcs11.SunPKCS11";

	private SunPKCS11Initializer() {
	}

	public static Provider getProvider(String configString) {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(configString.getBytes())) {
			Class<?> sunPkcs11ProviderClass = Class.forName(SUN_PKCS11_CLASSNAME);
			Constructor<?> constructor = sunPkcs11ProviderClass.getConstructor(InputStream.class);
			return (Provider) constructor.newInstance(bais);
		} catch (Exception e) {
			throw new DSSException("Unable to instantiate PKCS11 (JDK < 9) ", e);
		}
	}

}
