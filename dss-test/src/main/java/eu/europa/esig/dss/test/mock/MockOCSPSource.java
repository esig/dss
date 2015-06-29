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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.x509.ocsp.OfflineOCSPSource;


public class MockOCSPSource extends OfflineOCSPSource {

	protected List<BasicOCSPResp> ocspResponses = new ArrayList<BasicOCSPResp>();

	/**
	 * This constructor loads the OCSP responses from a array of <code>String</code>s representing resources.
	 *
	 * @param paths
	 */
	public MockOCSPSource(final String... paths) {

		for (final String pathItem : paths) {

			final InputStream inputStream = getClass().getResourceAsStream(pathItem);
			load(inputStream);
		}
	}

	/**
	 * This constructor loads the OCSP responses from a array of <code>InputStream</code>s.
	 *
	 * @param inputStreams
	 */
	public MockOCSPSource(final InputStream... inputStreams) {

		for (final InputStream inputStream : inputStreams) {

			load(inputStream);
		}
	}

	/**
	 * This method adds the OCSP basic ocspResponses to the general list.
	 *
	 * @param inputStream
	 */
	private void load(final InputStream inputStream) {

		try {

			final OCSPResp ocspResp = new OCSPResp(inputStream);
			final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
			ocspResponses.add(basicOCSPResp);
		} catch (Exception e) {

			throw new DSSException(e);
		}
	}

	@Override
	public List<BasicOCSPResp> getContainedOCSPResponses() {

		return ocspResponses;
	}
}
