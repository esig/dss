/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
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
package eu.europa.ec.markt.dss.validation102853.crl;

import java.io.InputStream;
import java.security.cert.X509CRL;
import java.util.ArrayList;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * This class allows to provide a mock CRL source based on the list of
 * individual CRL(s);
 *
 * @version $Revision$ - $Date$
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
		x509CRLList = new ArrayList<X509CRL>();
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
		x509CRLList = new ArrayList<X509CRL>();
		for (final InputStream inputStream : inputStreams) {
			addCRLToken(inputStream);
		}
	}

	private void addCRLToken(final InputStream inputStream) {
		final X509CRL x509CRL = DSSUtils.loadCRL(inputStream);
		if (!x509CRLList.contains(x509CRL)) {
			x509CRLList.add(x509CRL);
		}
	}
}
