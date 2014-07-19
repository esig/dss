/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2014 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2014 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.validation102853.scope;

import java.util.HashMap;
import java.util.Map;

import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.pades.PAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

/**
 * Factory that centralize which SignatureScopeFinder will be used for which AdvancedSignature.
 * <p/>
 * The class used can be customized by calling <code>getSignatureScopeFinderMap</code> and adding to the map a different SignatureScopeFinder implementation.
 *
 * The default are:
 * <pre>
 signatureScopeFinderMap.put(CAdESSignature.class, new CAdESSignatureScopeFinder());
 signatureScopeFinderMap.put(PAdESSignature.class, new PAdESSignatureScopeFinder());
 signatureScopeFinderMap.put(XAdESSignature.class, new XAdESSignatureScopeFinder());
 * </pre>
 *
 */
public class SignatureScopeFinderFactory {

	private static Map<Class<? extends AdvancedSignature>, SignatureScopeFinder> signatureScopeFinderMap = new HashMap<Class<? extends AdvancedSignature>, SignatureScopeFinder>();

	static {
		signatureScopeFinderMap.put(CAdESSignature.class, new CAdESSignatureScopeFinder());
		signatureScopeFinderMap.put(PAdESSignature.class, new PAdESSignatureScopeFinder());
		signatureScopeFinderMap.put(XAdESSignature.class, new XAdESSignatureScopeFinder());
	}

	public static <T extends AdvancedSignature> SignatureScopeFinder<T> geInstance(Class<T> advancedSignatureClass) {
		final SignatureScopeFinder signatureScopeFinder = signatureScopeFinderMap.get(advancedSignatureClass);
		if (signatureScopeFinder == null) {
			throw new IllegalStateException(
				  "The SignatureScopeFinderFactory shall contains a SignatureScopeFinder for AdvancedSignature class " + advancedSignatureClass.getName());
		} else {
			return signatureScopeFinder;
		}
	}

	/**
	 * @return the map that could be overridden to provide an other implementation of signature scope finder.
	 */
	public static Map<Class<? extends AdvancedSignature>, SignatureScopeFinder> getSignatureScopeFinderMap() {
		return signatureScopeFinderMap;
	}
}
