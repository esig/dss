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
package eu.europa.esig.dss.xml;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.keyresolver.KeyResolver;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Customized Initialization of Santuario.
 * 
 * We don't use the secureValidation parameter because it ignores some signature
 * algorithms
 *
 */
public class SantuarioInitializer {

	private static final Logger LOG = LoggerFactory.getLogger(SantuarioInitializer.class);

	/** Field alreadyInitialized */
	private static boolean alreadyInitialized = false;

	/**
	 * Empty constructor
	 */
	private SantuarioInitializer() {
		// empty
	}

	/**
	 * Method isInitialized
	 * 
	 * @return true if the library is already initialized.
	 */
	public static final synchronized boolean isInitialized() {
		if (Init.isInitialized()) {
			LOG.info("Santuario is already initialized with its default configuration");
			return true;
		}
		return SantuarioInitializer.alreadyInitialized;
	}

	/**
	 * Method init
	 *
	 */
	public static synchronized void init() {
		if (isInitialized()) {
			return;
		}

		dynamicInit();

		alreadyInitialized = true;
	}

	/**
	 * Dynamically initialise the library by registering the default
	 * algorithms/implementations
	 */
	private static void dynamicInit() {
		//
		// Load the Resource Bundle - the default is the English resource bundle.
		// To load another resource bundle, call I18n.init(...) before calling this
		// method.
		//
		I18n.init("en", "US");

		if (LOG.isDebugEnabled()) {
			LOG.debug("Registering default algorithms");
		}
		try {
			//
			// Bind the default prefixes
			//
			ElementProxy.registerDefaultPrefixes();
		} catch (XMLSecurityException ex) {
			LOG.error(ex.getMessage(), ex);
		}

		//
		// Set the default Transforms
		//
		Transform.registerDefaultAlgorithms();

		//
		// Set the default signature algorithms
		//
		SignatureAlgorithm.registerDefaultAlgorithms();

		//
		// Set the default c14n algorithms
		//
		Canonicalizer.registerDefaultAlgorithms();

		//
		// Register the default key resolvers
		//
		KeyResolver.registerDefaultResolvers();
	}

}
