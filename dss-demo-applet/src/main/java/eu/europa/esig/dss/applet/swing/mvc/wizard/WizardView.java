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
package eu.europa.esig.dss.applet.swing.mvc.wizard;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;

import javax.swing.JButton;
import javax.swing.JPanel;

import com.jgoodies.binding.beans.Model;

import eu.europa.esig.dss.applet.swing.mvc.AppletCore;
import eu.europa.esig.dss.applet.util.ComponentFactory;
import eu.europa.esig.dss.applet.util.ResourceUtils;
import eu.europa.esig.dss.applet.view.DSSAppletView;

/**
 *
 * TODO
 *
 *
 *
 *
 *
 *
 * @param <M>
 * @param <C>
 */

public abstract class WizardView<M extends Model, C extends WizardController<M>> extends DSSAppletView<M, C> {

	/**
	 *
	 * TODO
	 *
	 *
	 *
	 *
	 *
	 *
	 */
	private class BackActionListener implements ActionListener {
		/*
		 * (non-Javadoc)
		 *
		 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
		 */
		@Override
		public void actionPerformed(final ActionEvent event) {
			getController().doBack();
		}

	}

	/**
	 *
	 * TODO
	 *
	 *
	 *
	 *
	 *
	 *
	 */
	private class CancelActionListener implements ActionListener {
		/*
		 * (non-Javadoc)
		 *
		 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
		 */
		@Override
		public void actionPerformed(final ActionEvent event) {
			getController().doCancel();
		}
	}

	/**
	 *
	 * TODO
	 *
	 *
	 *
	 *
	 *
	 *
	 */
	private class NextActionListener implements ActionListener {
		/*
		 * (non-Javadoc)
		 *
		 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
		 */
		@Override
		public void actionPerformed(final ActionEvent event) {
			getController().doNext();
		}

	}

	private final JButton backButton;
	private final JButton nextButton;
	private final JButton cancelButton;

	/**
	 *
	 * The default constructor for WizardView.
	 *
	 * @param core
	 * @param controller
	 * @param model
	 */
	public WizardView(final AppletCore core, final C controller, final M model) {
		super(core, controller, model);

		backButton = ComponentFactory.createBackButton(false, new BackActionListener());
		backButton.setName("back");
		nextButton = ComponentFactory.createNextButton(false, new NextActionListener());
		nextButton.setName("next");
		cancelButton = ComponentFactory.createCancelButton(true, new CancelActionListener());
		cancelButton.setName("cancel");
	}

	private JPanel doActionLayout() {
		if (getController().hasNext()) {
			return ComponentFactory.actionPanel(backButton, nextButton, cancelButton);
		} else {
			return ComponentFactory.actionPanel(backButton, cancelButton);
		}

	}

	private JPanel doStepLayout() {
		final int currentStep = getController().getStepNumber();
		final int maxStep = getController().getStepTotals();
		return ComponentFactory.createWizardStepPanel(currentStep, maxStep);

	}

	private void doWizardInit() {
		final boolean backEnabled = getController().hasBack();
		final boolean nextEnabled = getController().hasNext() && getController().isValid();
		backButton.setEnabled(backEnabled);
		nextButton.setEnabled(nextEnabled);

		if (getController().isLast()) {
			nextButton.setText(ResourceUtils.getI18n("FINISH"));
		} else {
			nextButton.setText(ResourceUtils.getI18n("NEXT"));
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.view.DSSAppletView#layout()
	 */
	@Override
	protected Container layout() {

		doWizardInit();

		final JPanel panel = ComponentFactory.createPanel(new BorderLayout());

		panel.add(doStepLayout(), BorderLayout.NORTH);
		panel.add(super.layout(), BorderLayout.CENTER);
		panel.add(doActionLayout(), BorderLayout.SOUTH);

		return panel;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see eu.europa.esig.dss.applet.view.DSSAppletView#modelChange(java.beans.PropertyChangeEvent)
	 */
	@Override
	public void modelChanged(final PropertyChangeEvent evt) {

		final boolean enabled = getController().hasNext() && getController().isValid();

		this.nextButton.setEnabled(enabled);

		wizardModelChange(evt);
	}

	public void wizardModelChange(final PropertyChangeEvent evt) {
	};

}
