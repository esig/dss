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
package eu.europa.esig.dss.x509.ocsp;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public class ListOCSPSource extends OfflineOCSPSource {

	protected List<BasicOCSPResp> basicOCSPRespList = null;

	public ListOCSPSource() {

		basicOCSPRespList = new ArrayList<BasicOCSPResp>();
	}

	/**
	 * This constructor allows to initialize the list of {@code BasicOCSPResp} from an {@code OfflineOCSPSource}.
	 *
	 * @param ocspSource
	 */
	public ListOCSPSource(final OfflineOCSPSource ocspSource) {

		basicOCSPRespList = new ArrayList<BasicOCSPResp>(ocspSource.getContainedOCSPResponses());
	}

	@Override
	public List<BasicOCSPResp> getContainedOCSPResponses() {
		return basicOCSPRespList;
	}

	/**
	 * This method allows to add all {@code BasicOCSPResp} from one {@code OfflineOCSPSource} to this one. If the {@code BasicOCSPResp} exists already within the current source
	 * then it is ignored.
	 *
	 * @param offlineOCSPSource the source to be added
	 */
	public void addAll(final OfflineOCSPSource offlineOCSPSource) {

		for (BasicOCSPResp basicOCSPResp : offlineOCSPSource.getContainedOCSPResponses()) {

			if (!basicOCSPRespList.contains(basicOCSPResp)) {
				basicOCSPRespList.add(basicOCSPResp);
			}
		}
	}
}
