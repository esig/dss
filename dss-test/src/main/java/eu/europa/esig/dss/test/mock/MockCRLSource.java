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
package eu.europa.esig.dss.test.mock;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;

/**
 * This class allows to provide a mock CRL source based on the list of
 * individual CRL(s);
 *
 */
public class MockCRLSource extends OfflineCRLSource {

	private static final long serialVersionUID = -985602836642741439L;

	/**
	 * This constructor allows to build a mock CRL source from a list of
	 * resource paths.
	 *
	 * @param paths
	 */
	public MockCRLSource(final String... paths) {
		for (final String pathItem : paths) {
			final InputStream inputStream = getClass().getResourceAsStream(pathItem);
			addCRLToken(inputStream);
		}
	}

	/**
	 * This constructor allows to build a mock CRL source from a list of
	 * <code>InputStream</code>.
	 *
	 * @param inputStreams
	 *            the list of <code>InputStream</code>
	 */
	public MockCRLSource(final InputStream... inputStreams) {
		for (final InputStream inputStream : inputStreams) {
			addCRLToken(inputStream);
		}
	}

	/**
	 * This constructor allows to build a mock CRL source from a list of
	 * <code>X509CRL</code>.
	 *
	 * @param crls
	 *            the list of <code>X509CRL</code>
	 */
	public MockCRLSource(final X509CRL... crls) {
		for (X509CRL x509crl : crls) {
			try {
				addCRLBinary(x509crl.getEncoded());
			} catch (CRLException e) {
				throw new DSSException(e);
			}
		}
	}

	private void addCRLToken(final InputStream inputStream) {
		try {
			addCRLBinary(Utils.toByteArray(inputStream));
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
}
