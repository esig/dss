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
package eu.europa.esig.dss.applet.controller;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.europa.esig.dss.applet.main.DSSAppletCore;
import eu.europa.esig.dss.applet.main.Parameters;
import eu.europa.esig.dss.applet.swing.mvc.AppletController;

/**
 * TODO
 *
 */
public abstract class DSSAppletController<M> extends AppletController<DSSAppletCore, M> {

	protected final String serviceURL;

	/**
	 * The default constructor for DSSAppletController.
	 *
	 * @param core
	 * @param model
	 */
	protected DSSAppletController(final DSSAppletCore core, final M model) {
		super(core, model);

		Security.addProvider(new BouncyCastleProvider());

		final Parameters parameters = core.getParameters();

		serviceURL = parameters.getServiceURL();

	}

	/**
	 * @return
	 */
	public Parameters getParameter() {
		return getCore().getParameters();
	}

}
