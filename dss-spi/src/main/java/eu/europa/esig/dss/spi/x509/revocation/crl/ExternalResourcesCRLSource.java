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
package eu.europa.esig.dss.spi.x509.revocation.crl;

import java.io.IOException;
import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class allows to provide a CRL source based on the list of external CRL(s);
 */
public class ExternalResourcesCRLSource extends OfflineCRLSource {

	private static final long serialVersionUID = -985602836642741439L;

	private static final Logger LOG = LoggerFactory.getLogger(ExternalResourcesCRLSource.class);

	/**
	 * This constructor allows to build a CRL source from a list of
	 * resource paths.
	 *
	 * @param paths
	 *            paths to be loaded as CRL
	 */
	public ExternalResourcesCRLSource(final String... paths) {
		for (final String pathItem : paths) {
			try {
				addCRLToken(getClass().getResourceAsStream(pathItem));
			} catch (Exception e) {
				LOG.error("Unable to load '" + pathItem + "'", e);
			}
		}
	}

	/**
	 * This constructor allows to build a CRL source from a list of
	 * <code>InputStream</code>.
	 *
	 * @param inputStreams
	 *            the list of <code>InputStream</code> to be loaded as CRL
	 */
	public ExternalResourcesCRLSource(final InputStream... inputStreams) {
		for (final InputStream inputStream : inputStreams) {
			addCRLToken(inputStream);
		}
	}

	private void addCRLToken(final InputStream inputStream) {
		try (InputStream is = inputStream) {
			addBinary(CRLUtils.buildCRLBinary(Utils.toByteArray(is)), RevocationOrigin.EXTERNAL);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

}
