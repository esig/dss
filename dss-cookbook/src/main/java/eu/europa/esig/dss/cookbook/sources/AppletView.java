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
package eu.europa.esig.dss.cookbook.sources;

import java.awt.Component;

import javax.swing.JApplet;

import be.fedict.eid.applet.DiagnosticTests;
import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.Status;
import be.fedict.eid.applet.View;


public class AppletView implements View {

	private JApplet applet;

	/**
	 * The default constructor for AppletView.
	 */
	public AppletView(JApplet applet) {

		this.applet = applet;
	}

	@Override
	public void addDetailMessage(String detailMessage) {
	}

	@Override
	public Component getParentComponent() {

		return applet;
	}

	@Override
	public boolean privacyQuestion(boolean includeAddress, boolean includePhoto, String identityDataUsage) {

		return false;
	}

	@Override
	public void setStatusMessage(Status status, Messages.MESSAGE_ID messageId) {
	}


	@Override
	public void setProgressIndeterminate() {
	}

	@Override
	public void resetProgress(int max) {
	}

	@Override
	public void increaseProgress() {
	}

	@Override
	public void addTestResult(DiagnosticTests arg0, boolean arg1, String arg2) {
	}
}

