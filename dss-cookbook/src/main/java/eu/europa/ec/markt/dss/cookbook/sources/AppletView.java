package eu.europa.ec.markt.dss.cookbook.sources;

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

