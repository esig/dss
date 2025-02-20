/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xml.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.transform.ErrorListener;
import javax.xml.transform.TransformerException;

/**
 * The DSS implementation of {@code ErrorListener}
 * Logs errors according to its level
 */
public class DSSXmlErrorListener implements ErrorListener {

	private static final Logger LOG = LoggerFactory.getLogger(DSSXmlErrorListener.class);

	/**
	 * Default constructor
	 */
	public DSSXmlErrorListener() {
		// empty
	}

	@Override
	public void warning(TransformerException e) throws TransformerException {
		LOG.warn(e.getMessage(), e);
		throw e;
	}

	@Override
	public void error(TransformerException e) throws TransformerException {
		LOG.error(e.getMessage(), e);
		throw e;
	}

	@Override
	public void fatalError(TransformerException e) throws TransformerException {
		LOG.error(e.getMessage(), e);
		throw e;
	}

}
